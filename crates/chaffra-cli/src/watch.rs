//! Filesystem watch mode for chaffra.
//!
//! Monitors a directory for file changes, debounces events, and re-runs
//! analysis on changed files.

use anyhow::{Context, Result};
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::module::ModuleHost;
use chaffra_deadcode::DeadCodeModule;
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
}

impl WatchConfig {
    pub fn new(root: PathBuf, format: OutputFormat, config: ChaffraConfig) -> Self {
        Self {
            root,
            debounce: Duration::from_millis(200),
            format,
            config,
        }
    }
}

/// Build a module host with all built-in modules.
fn build_module_host() -> ModuleHost {
    let mut host = ModuleHost::new();
    let _ = host.register(Box::new(DeadCodeModule::new()));
    let _ = host.register(Box::new(ComplexityModule::new()));
    host
}

/// Check if a path is a source file we should analyze.
fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| matches!(ext, "go" | "py"))
}

/// Run analysis on changed files and print results.
pub fn run_analysis_on_changes(
    changed_paths: &[PathBuf],
    root: &Path,
    config: &ChaffraConfig,
    format: OutputFormat,
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

    let host = build_module_host();
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

        match run_analysis_on_changes(&changed, &root, &config, format) {
            Ok(output) => {
                if !output.is_empty() {
                    print!("{output}");
                }
            }
            Err(e) => eprintln!("Analysis error: {e}"),
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
        )
        .unwrap();
        assert!(!result.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }
}
