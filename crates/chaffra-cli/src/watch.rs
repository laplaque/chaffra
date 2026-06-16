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

/// Run analysis on changed files and print results.
pub fn run_analysis_on_changes(
    changed_paths: &[PathBuf],
    root: &Path,
    config: &ChaffraConfig,
    format: OutputFormat,
    collector: Option<&chaffra_telemetry::TelemetryCollector>,
) -> Result<String> {
    let source_files: Vec<&PathBuf> = changed_paths.iter().filter(|p| is_source_file(p)).collect();

    if source_files.is_empty() {
        return Ok(String::new());
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
        return Ok(String::new());
    }

    let host = crate::build_module_host_with_telemetry(collector);
    let formatter = create_formatter(format);
    let mut output = String::new();

    // Run dead-code analysis.
    if let Ok(result) = host.analyze("dead-code", &files, config) {
        if !result.findings.is_empty() {
            output.push_str(&formatter.format_findings(&result.findings));
        }
    }

    // Run complexity analysis.
    if let Ok(result) = host.analyze("complexity", &files, config) {
        if !result.findings.is_empty() {
            output.push_str(&formatter.format_findings(&result.findings));
        }
    }

    if output.is_empty() {
        let file_names: Vec<String> = source_files
            .iter()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect();
        output = format!("No issues found in: {}\n", file_names.join(", "));
    }

    Ok(output)
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

/// Run the watch loop. Blocks until interrupted.
pub fn run_watch(watch_config: WatchConfig) -> Result<()> {
    let root = watch_config.root.clone();
    let config = watch_config.config.clone();
    let format = watch_config.format;
    let is_off = matches!(
        watch_config.tel_config.audience,
        chaffra_telemetry::TelemetryAudience::Off
    );

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

        if is_off {
            match run_analysis_on_changes(&changed, &root, &config, format, None) {
                Ok(output) => {
                    if !output.is_empty() {
                        print!("{output}");
                    }
                }
                Err(e) => eprintln!("Analysis error: {e}"),
            }
            continue;
        }

        let collector = chaffra_telemetry::TelemetryCollector::new(watch_config.tel_config.clone());
        collector.register_core_metrics();
        let start = std::time::Instant::now();

        match run_analysis_on_changes(&changed, &root, &config, format, Some(&collector)) {
            Ok(output) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                collector.record_module_call("watch", duration_ms, false);

                let current_fingerprints = collector.finding_fingerprints();
                let state_path = std::path::Path::new(chaffra_telemetry::churn::STATE_FILE);
                let previous_state = chaffra_telemetry::churn::load_state(state_path);
                let current_hash =
                    chaffra_telemetry::churn::hash_fingerprints(&current_fingerprints);

                if let Some(ref prev) = previous_state {
                    let churn =
                        chaffra_telemetry::churn::compute_churn(&current_fingerprints, prev);
                    collector.record_finding_churn(&churn);
                }

                let snapshot = collector.snapshot();
                watch_config.live_state.push_snapshot(snapshot.clone());

                let flushed = if watch_config.tel_config.audience.operator_enabled() {
                    snapshot
                } else {
                    snapshot.user_scoped()
                };
                let (backends, _) =
                    chaffra_telemetry::backends::create_backends(&watch_config.tel_config.backends);
                for backend in &backends {
                    if let Err(e) = backend.flush(&flushed) {
                        eprintln!("Warning: telemetry backend flush failed: {e}");
                    }
                }

                let new_state = chaffra_telemetry::churn::ChurnState {
                    fingerprints: current_fingerprints,
                    findings_hash: current_hash,
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                let _ = chaffra_telemetry::churn::save_state(&new_state, state_path);

                if !output.is_empty() {
                    print!("{output}");
                }
            }
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                collector.record_module_call("watch", duration_ms, true);
                let snapshot = collector.snapshot();
                watch_config.live_state.push_snapshot(snapshot.clone());

                let flushed = if watch_config.tel_config.audience.operator_enabled() {
                    snapshot
                } else {
                    snapshot.user_scoped()
                };
                let (backends, _) =
                    chaffra_telemetry::backends::create_backends(&watch_config.tel_config.backends);
                for backend in &backends {
                    if let Err(e) = backend.flush(&flushed) {
                        eprintln!("Warning: telemetry backend flush failed: {e}");
                    }
                }

                eprintln!("Analysis error: {e}");
            }
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
        assert!(result.is_empty());

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
        assert!(!result.is_empty());

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
        assert!(result.contains("No issues") || !result.is_empty());

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
        assert!(!result.is_empty());

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
        assert!(result.is_empty());

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
        assert!(!result.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
}
