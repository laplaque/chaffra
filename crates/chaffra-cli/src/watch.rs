//! Filesystem watch mode for chaffra.
//!
//! Monitors a directory for file changes, debounces events, and re-runs
//! analysis on changed files.

use anyhow::{Context, Result};
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::FileInfo;
use chaffra_output::{OutputFormat, create_formatter};
use notify_debouncer_full::{DebouncedEvent, new_debouncer, notify::RecursiveMode};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

/// Configuration for watch mode.
pub struct WatchConfig {
    /// Root directory to watch.
    pub root: PathBuf,
    /// Debounce duration.
    pub debounce: Duration,
    /// Output format.
    pub format: OutputFormat,
    /// Chaffra config.
    pub config: ChaffraConfig,
    /// Telemetry config for watch iterations.
    pub tel_config: chaffra_telemetry::TelemetryConfig,
    /// Shared live telemetry state.
    pub live_state: chaffra_telemetry::LiveTelemetryState,
}

impl WatchConfig {
    pub fn new(
        root: PathBuf,
        format: OutputFormat,
        config: ChaffraConfig,
        tel_config: chaffra_telemetry::TelemetryConfig,
        live_state: chaffra_telemetry::LiveTelemetryState,
    ) -> Self {
        Self {
            root,
            debounce: Duration::from_millis(200),
            format,
            config,
            tel_config,
            live_state,
        }
    }
}

/// Check if a path is a source file we should analyze.
/// Covers all languages supported by chaffra's tree-sitter parsing.
fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            matches!(
                ext,
                "go" | "py"
                    | "js"
                    | "jsx"
                    | "ts"
                    | "tsx"
                    | "java"
                    | "c"
                    | "h"
                    | "cpp"
                    | "cc"
                    | "cxx"
                    | "hpp"
                    | "rs"
            )
        })
}

/// Analysis result: formatted output and raw findings for telemetry.
pub struct AnalysisOutput {
    pub text: String,
    pub findings: Vec<chaffra_core::diagnostic::Finding>,
    pub had_module_error: bool,
}

/// Run analysis on changed files and print results.
pub fn run_analysis_on_changes(
    changed_paths: &[PathBuf],
    root: &Path,
    config: &ChaffraConfig,
    format: OutputFormat,
    collector: Option<&chaffra_telemetry::TelemetryCollector>,
) -> Result<AnalysisOutput> {
    let source_files: Vec<&PathBuf> = changed_paths.iter().filter(|p| is_source_file(p)).collect();

    if source_files.is_empty() {
        return Ok(AnalysisOutput {
            text: String::new(),
            findings: Vec::new(),
            had_module_error: false,
        });
    }

    let files: Vec<FileInfo> = source_files
        .iter()
        .filter_map(|p| {
            let content = std::fs::read(p).ok()?;
            let relative = p
                .strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .to_string();
            Some(FileInfo {
                path: relative,
                content,
            })
        })
        .collect();

    if files.is_empty() {
        return Ok(AnalysisOutput {
            text: String::new(),
            findings: Vec::new(),
            had_module_error: false,
        });
    }

    let host = crate::build_module_host_with_telemetry(collector);
    let formatter = create_formatter(format);
    let mut output = String::new();
    let mut all_findings = Vec::new();
    let mut had_module_error = false;

    for module_id in &["dead-code", "complexity"] {
        let start = std::time::Instant::now();
        match host.analyze(module_id, &files, config) {
            Ok(result) => {
                if let Some(c) = collector {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    c.record_module_call(module_id, duration_ms, false);
                    let mut sev_counts = std::collections::HashMap::new();
                    for finding in &result.findings {
                        let sev = match finding.severity {
                            chaffra_core::diagnostic::Severity::Error => "error",
                            chaffra_core::diagnostic::Severity::Warning => "warning",
                            chaffra_core::diagnostic::Severity::Info => "info",
                        };
                        *sev_counts.entry(sev.to_owned()).or_insert(0u64) += 1;
                    }
                    c.record_module_findings(module_id, result.findings.len() as u64, &sev_counts);
                }
                if !result.findings.is_empty() {
                    output.push_str(&formatter.format_findings(&result.findings));
                }
                all_findings.extend(result.findings);
            }
            Err(_) => {
                if let Some(c) = collector {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    c.record_module_call(module_id, duration_ms, true);
                }
                had_module_error = true;
            }
        }
    }

    if output.is_empty() {
        let file_names: Vec<String> = source_files
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        output = format!("No issues found in: {}\n", file_names.join(", "));
    }

    Ok(AnalysisOutput {
        text: output,
        findings: all_findings,
        had_module_error,
    })
}

/// Extract changed file paths from debounced events.
pub fn extract_changed_paths(events: &[DebouncedEvent]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for event in events {
        for path in &event.event.paths {
            if path.is_file() && is_source_file(path) && !paths.contains(path) {
                paths.push(path.clone());
            }
        }
    }
    paths
}

/// Run a single watch iteration: analyze changed files, emit output, handle
/// telemetry. Returns `Some(text)` with the formatted output on success, or
/// `None` on analysis error.
///
/// `project_fingerprints` accumulates per-file fingerprints across iterations
/// so that churn is computed against the full project, not just the changed files.
pub(crate) fn run_watch_iteration(
    changed: &[PathBuf],
    root: &Path,
    config: &ChaffraConfig,
    format: OutputFormat,
    watch_config: &WatchConfig,
    project_fingerprints: &mut std::collections::HashMap<
        String,
        std::collections::HashSet<chaffra_telemetry::churn::FindingFingerprint>,
    >,
) -> Option<String> {
    let is_off = matches!(
        watch_config.tel_config.audience,
        chaffra_telemetry::TelemetryAudience::Off
    );

    if is_off {
        return match run_analysis_on_changes(changed, root, config, format, None) {
            Ok(ao) => Some(ao.text),
            Err(_) => None,
        };
    }

    let collector = chaffra_telemetry::TelemetryCollector::new(watch_config.tel_config.clone());
    collector.register_core_metrics();
    let start = std::time::Instant::now();

    match run_analysis_on_changes(changed, root, config, format, Some(&collector)) {
        Ok(ao) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            collector.record_module_call("watch", duration_ms, ao.had_module_error);

            let analyzed_files: std::collections::HashSet<String> = changed
                .iter()
                .filter_map(|p| {
                    p.strip_prefix(root)
                        .unwrap_or(p)
                        .to_str()
                        .map(|s| s.to_owned())
                })
                .collect();
            for file in &analyzed_files {
                project_fingerprints.remove(file);
            }
            for fp in crate::fingerprints_from_findings(&ao.findings) {
                project_fingerprints
                    .entry(fp.file.clone())
                    .or_default()
                    .insert(fp);
            }
            let all_fingerprints: std::collections::HashSet<_> = project_fingerprints
                .values()
                .flat_map(|s| s.iter().cloned())
                .collect();
            collector.set_finding_fingerprints(all_fingerprints);

            chaffra_telemetry::finalize_and_flush_sampled(
                &collector,
                &watch_config.live_state,
                &watch_config.tel_config,
                &watch_config.root,
            );

            Some(ao.text)
        }
        Err(_) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            collector.record_module_call("watch", duration_ms, true);
            chaffra_telemetry::flush_snapshot(
                &collector,
                &watch_config.live_state,
                &watch_config.tel_config,
            );

            None
        }
    }
}

/// Run the watch loop. Blocks until interrupted.
pub fn run_watch(watch_config: WatchConfig) -> Result<()> {
    let root = watch_config.root.clone();
    let config = watch_config.config.clone();
    let format = watch_config.format;
    let mut project_fingerprints = std::collections::HashMap::new();

    eprintln!(
        "Watching {} for changes (debounce: {}ms)...",
        root.display(),
        watch_config.debounce.as_millis()
    );

    let (tx, rx) = mpsc::channel();

    let mut debouncer = new_debouncer(watch_config.debounce, None, move |result| {
        if let Ok(events) = result {
            let _ = tx.send(events);
        }
    })
    .context("failed to create file watcher")?;

    debouncer
        .watch(&root, RecursiveMode::Recursive)
        .context("failed to start watching directory")?;

    while let Ok(events) = rx.recv() {
        let changed = extract_changed_paths(&events);
        if changed.is_empty() {
            continue;
        }

        eprintln!("\n--- Change detected: {} file(s) ---", changed.len());

        match run_watch_iteration(
            &changed,
            &root,
            &config,
            format,
            &watch_config,
            &mut project_fingerprints,
        ) {
            Some(text) if !text.is_empty() => print!("{text}"),
            Some(_) => {}
            None => eprintln!("Analysis error"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_is_source_file() {
        assert!(is_source_file(Path::new("main.go")));
        assert!(is_source_file(Path::new("app.py")));
        assert!(is_source_file(Path::new("index.js")));
        assert!(is_source_file(Path::new("App.jsx")));
        assert!(is_source_file(Path::new("index.ts")));
        assert!(is_source_file(Path::new("App.tsx")));
        assert!(is_source_file(Path::new("Main.java")));
        assert!(is_source_file(Path::new("main.c")));
        assert!(is_source_file(Path::new("util.h")));
        assert!(is_source_file(Path::new("main.cpp")));
        assert!(is_source_file(Path::new("main.cc")));
        assert!(is_source_file(Path::new("main.rs")));
        assert!(!is_source_file(Path::new("readme.md")));
        assert!(!is_source_file(Path::new("Cargo.toml")));
        assert!(!is_source_file(Path::new("no_extension")));
    }

    #[test]
    fn test_watch_config_new() {
        let config = WatchConfig::new(
            PathBuf::from("/tmp"),
            OutputFormat::Terminal,
            ChaffraConfig::default(),
            chaffra_telemetry::TelemetryConfig::default(),
            chaffra_telemetry::LiveTelemetryState::new(),
        );
        assert_eq!(config.root, PathBuf::from("/tmp"));
        assert_eq!(config.debounce, Duration::from_millis(200));
        assert_eq!(config.format, OutputFormat::Terminal);
    }

    #[test]
    fn test_run_analysis_no_source_files() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_no_src");
        let _ = fs::create_dir_all(&dir);
        let readme = dir.join("readme.md");
        fs::write(&readme, "# Test").unwrap();

        let result = run_analysis_on_changes(
            &[readme],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            None,
        )
        .unwrap();
        assert!(result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_analysis_with_go_file() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_go");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let go_file = dir.join("main.go");
        fs::write(
            &go_file,
            "package main\n\nfunc main() {}\n\nfunc unused() {}\n",
        )
        .unwrap();

        let result = run_analysis_on_changes(
            &[go_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            None,
        )
        .unwrap();
        // Should produce some output (either findings or "no issues").
        assert!(!result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_analysis_clean_file() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_clean");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let go_file = dir.join("main.go");
        fs::write(&go_file, "package main\n\nfunc main() {}\n").unwrap();

        let result = run_analysis_on_changes(
            &[go_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            None,
        )
        .unwrap();
        assert!(result.text.contains("No issues") || !result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_analysis_with_json_format() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let go_file = dir.join("main.go");
        fs::write(
            &go_file,
            "package main\n\nfunc main() {}\n\nfunc unused() {}\n",
        )
        .unwrap();

        let result = run_analysis_on_changes(
            &[go_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Json,
            None,
        )
        .unwrap();
        assert!(!result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_analysis_nonexistent_file() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_nofile");
        let _ = fs::create_dir_all(&dir);

        let result = run_analysis_on_changes(
            &[dir.join("nonexistent.go")],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            None,
        )
        .unwrap();
        // Nonexistent file should produce empty result.
        assert!(result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_analysis_python_file() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_py");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let py_file = dir.join("app.py");
        fs::write(&py_file, "import os\n\ndef main():\n    pass\n").unwrap();

        let result = run_analysis_on_changes(
            &[py_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            None,
        )
        .unwrap();
        assert!(!result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_analysis_with_collector_severity_counting() {
        let dir = std::env::temp_dir().join("chaffra_watch_test_sev");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let go_file = dir.join("main.go");
        fs::write(
            &go_file,
            "package main\n\nfunc main() {}\n\nfunc unused() {}\n",
        )
        .unwrap();

        let tel_config = chaffra_telemetry::TelemetryConfig::default();
        let collector = chaffra_telemetry::TelemetryCollector::new(tel_config);
        collector.register_core_metrics();

        let result = run_analysis_on_changes(
            &[go_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            Some(&collector),
        )
        .unwrap();
        // Should produce output and findings (severity counting path exercised).
        assert!(!result.text.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_watch_iteration_telemetry_off() {
        let dir = std::env::temp_dir().join("chaffra_watch_iter_off");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let go_file = dir.join("main.go");
        fs::write(
            &go_file,
            "package main\n\nfunc main() {}\n\nfunc unused() {}\n",
        )
        .unwrap();

        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::Off,
            ..Default::default()
        };

        let watch_cfg = WatchConfig::new(
            dir.clone(),
            OutputFormat::Terminal,
            ChaffraConfig::default(),
            tel_config,
            chaffra_telemetry::LiveTelemetryState::new(),
        );

        let mut project_fps = std::collections::HashMap::new();
        let result = run_watch_iteration(
            &[go_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            &watch_cfg,
            &mut project_fps,
        );
        assert!(result.is_some(), "telemetry-off iteration should succeed");
        assert!(!result.unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_watch_iteration_with_telemetry() {
        let dir = std::env::temp_dir().join("chaffra_watch_iter_tel");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let go_file = dir.join("main.go");
        fs::write(
            &go_file,
            "package main\n\nfunc main() {}\n\nfunc unused() {}\n",
        )
        .unwrap();

        let watch_cfg = WatchConfig::new(
            dir.clone(),
            OutputFormat::Terminal,
            ChaffraConfig::default(),
            chaffra_telemetry::TelemetryConfig::default(),
            chaffra_telemetry::LiveTelemetryState::new(),
        );

        let mut project_fps = std::collections::HashMap::new();
        let result = run_watch_iteration(
            &[go_file],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            &watch_cfg,
            &mut project_fps,
        );
        assert!(
            result.is_some(),
            "telemetry-on iteration should succeed on a valid file"
        );
        assert!(!result.unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_watch_iteration_no_source_files() {
        let dir = std::env::temp_dir().join("chaffra_watch_iter_nosrc");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let readme = dir.join("readme.md");
        fs::write(&readme, "# Test").unwrap();

        let watch_cfg = WatchConfig::new(
            dir.clone(),
            OutputFormat::Terminal,
            ChaffraConfig::default(),
            chaffra_telemetry::TelemetryConfig::default(),
            chaffra_telemetry::LiveTelemetryState::new(),
        );

        let mut project_fps = std::collections::HashMap::new();
        let result = run_watch_iteration(
            &[readme],
            &dir,
            &ChaffraConfig::default(),
            OutputFormat::Terminal,
            &watch_cfg,
            &mut project_fps,
        );
        // Non-source files should produce empty output (not None).
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
}
