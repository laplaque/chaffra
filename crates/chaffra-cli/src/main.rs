//! chaffra -- codebase intelligence CLI.

use anyhow::{Context, Result};
use chaffra_autofix::AutofixModule;
use chaffra_autofix::hooks;
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::{CONFIG_FILE_NAME, CONFIG_TEMPLATE, ChaffraConfig};
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::module::ModuleHost;
use chaffra_deadcode::DeadCodeModule;
use chaffra_frameworks::FrameworksModule;
use chaffra_output::{OutputFormat, create_formatter};
use chaffra_security::SecurityModule;
use chaffra_tui::App;
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::Path;

#[derive(Parser)]
#[command(
    name = "chaffra",
    version,
    about = "Codebase intelligence: dead code, complexity, health, duplicates, and more",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Output format: json, markdown, terminal.
    #[arg(long, global = true, default_value = "terminal")]
    format: String,

    /// Path to configuration file.
    #[arg(long, global = true)]
    config: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Compute and display a composite health score for the codebase.
    Health {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Detect dead code: unused functions, types, imports, and files.
    #[command(name = "dead-code")]
    DeadCode {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Find duplicate code blocks across the codebase.
    Dupes {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Run a PR audit: compare against baseline and emit a pass/fail verdict.
    Audit {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Run security analysis: SAST, secret scanning, and dependency CVE checks.
    Security {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Watch for file changes and re-run analysis incrementally.
    Watch {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Apply automated fixes for flagged issues where safe to do so.
    Fix {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,

        /// Preview fixes without applying them.
        #[arg(long)]
        dry_run: bool,

        /// Apply fixes for a specific rule only.
        #[arg(long)]
        rule: Option<String>,
    },
    /// Manage pre-commit hooks.
    Hooks {
        #[command(subcommand)]
        action: HooksAction,
    },
    /// Launch the terminal UI for browsing findings.
    Tui {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Explain a specific diagnostic rule in plain language.
    Explain {
        /// Rule ID to explain (e.g. "dead-code:unused-function").
        id: String,
    },
    /// Initialise a `.chaffra.toml` configuration file in the current directory.
    Init,
    /// List all registered analysis modules.
    Modules,
    /// Track impact: save snapshots and compare trends over time.
    Impact {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,

        /// Save a snapshot to the given file path.
        #[arg(long, value_name = "PATH")]
        save_snapshot: Option<String>,

        /// Compare against a baseline snapshot file.
        #[arg(long, value_name = "PATH")]
        baseline: Option<String>,

        /// Optional label for the snapshot (e.g. git ref).
        #[arg(long)]
        label: Option<String>,
    },
    /// Migrate configuration from another analysis tool to `.chaffra.toml`.
    Migrate {
        /// Source tool to migrate from (knip, jscpd, golangci-lint, ruff, import-linter).
        #[arg(long)]
        from: String,

        /// Path to the project directory containing the tool's config.
        #[arg(default_value = ".")]
        path: String,

        /// Write the generated config to `.chaffra.toml` instead of stdout.
        #[arg(long)]
        write: bool,
    },
    /// Detect monorepo workspace members.
    Workspaces {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
}

#[derive(Subcommand)]
enum HooksAction {
    /// Install the chaffra pre-commit hook.
    Install {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Uninstall the chaffra pre-commit hook.
    Uninstall {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
}

fn build_module_host() -> ModuleHost {
    let mut host = ModuleHost::new();
    // Register built-in modules.
    let _ = host.register(Box::new(DeadCodeModule::new()));
    let _ = host.register(Box::new(ComplexityModule::new()));
    let _ = host.register(Box::new(SecurityModule::new()));
    let _ = host.register(Box::new(FrameworksModule::new()));
    let _ = host.register(Box::new(AutofixModule::new()));
    host
}

fn load_config(config_path: Option<&str>, analysis_path: &Path) -> Result<ChaffraConfig> {
    if let Some(path) = config_path {
        ChaffraConfig::load(Path::new(path)).context("failed to load configuration file")
    } else {
        Ok(ChaffraConfig::load_from_dir(analysis_path).unwrap_or_default())
    }
}

fn discover_and_read_files(root: &Path, config: &ChaffraConfig) -> Vec<FileInfo> {
    let discovered = chaffra_parse::discovery::discover_files(root, &config.project.ignore);

    discovered
        .iter()
        .filter_map(|df| {
            let content = std::fs::read(&df.path).ok()?;
            Some(FileInfo {
                path: df.relative_path.clone(),
                content,
            })
        })
        .collect()
}

fn cmd_health(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let health = chaffra_complexity::analyze_project_health(
        &files,
        config.health.max_cyclomatic,
        config.health.max_cognitive,
    )?;
    Ok(formatter.format_health(&health))
}

fn cmd_dead_code(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host();
    let result = host.analyze("dead-code", &files, config)?;
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_security(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
) -> Result<String> {
    let mut files = discover_and_read_files(root, config);

    discover_security_files(root, root, &mut files);

    if files.is_empty() {
        return Ok("No files found.\n".to_owned());
    }
    let host = build_module_host();
    let result = host.analyze("security", &files, config)?;
    Ok(formatter.format_findings(&result.findings))
}

const SECURITY_SCAN_EXTENSIONS: &[&str] = &[
    "env",
    "toml",
    "yaml",
    "yml",
    "json",
    "cfg",
    "ini",
    "conf",
    "properties",
];

const MANIFEST_NAMES: &[&str] = &[
    "go.mod",
    "go.sum",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Cargo.lock",
    "Cargo.toml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "pubspec.lock",
    "Gemfile.lock",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "vendor",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".venv",
    "venv",
];

fn discover_security_files(root: &Path, dir: &Path, files: &mut Vec<FileInfo>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            discover_security_files(root, &path, files);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            if files.iter().any(|f| f.path == rel) {
                continue;
            }

            let is_manifest = MANIFEST_NAMES.iter().any(|m| name.as_ref() == *m);
            let is_security_ext = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|ext| SECURITY_SCAN_EXTENSIONS.contains(&ext));
            let is_dotenv = name.starts_with(".env");

            if is_manifest || is_security_ext || is_dotenv {
                if let Ok(content) = std::fs::read(&path) {
                    if content.len() <= 10 * 1024 * 1024 {
                        files.push(FileInfo { path: rel, content });
                    }
                }
            }
        }
    }
}

fn cmd_fix(
    root: &Path,
    config: &ChaffraConfig,
    dry_run: bool,
    rule: Option<&str>,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }

    let host = build_module_host();

    // Run analysis to collect findings.
    let dead_code_result = host.analyze("dead-code", &files, config)?;
    let mut all_findings = dead_code_result.findings;

    // Optionally filter by rule.
    if let Some(rule_id) = rule {
        all_findings.retain(|f| f.rule_id == rule_id);
    }

    // Collect fixable findings.
    let fixable = chaffra_autofix::collect_fixable(&all_findings);
    if fixable.is_empty() {
        return Ok("No auto-fixable findings.\n".to_owned());
    }

    // Orchestrate fixes.
    let fixable_owned: Vec<_> = fixable.into_iter().cloned().collect();
    let results = chaffra_autofix::orchestrate_fixes(&fixable_owned, dry_run)?;

    // If not dry run, apply edits to files on disk.
    if !dry_run {
        // Read current file contents.
        let mut file_contents: HashMap<String, String> = HashMap::new();
        for result in &results {
            for edit in &result.edits {
                if !file_contents.contains_key(&edit.file) {
                    let full_path = root.join(&edit.file);
                    if let Ok(content) = std::fs::read_to_string(&full_path) {
                        file_contents.insert(edit.file.clone(), content);
                    }
                }
            }
        }

        let new_contents = chaffra_autofix::apply_fixes_to_files(&file_contents, &results);
        for (file, content) in &new_contents {
            let full_path = root.join(file);
            std::fs::write(&full_path, content)
                .with_context(|| format!("failed to write {file}"))?;
        }
    }

    // Format output.
    let mut out = String::new();
    let applied = results.iter().filter(|r| r.applied).count();
    let skipped = results.iter().filter(|r| !r.applied).count();

    if dry_run {
        out.push_str(&format!(
            "Dry run: {} fixes would be applied, {} skipped.\n",
            results.iter().filter(|r| r.reason == "dry run").count(),
            results.iter().filter(|r| r.reason != "dry run").count(),
        ));
    } else {
        out.push_str(&format!("Applied {applied} fixes, skipped {skipped}.\n"));
    }

    for result in &results {
        let status = if result.applied { "APPLIED" } else { "SKIPPED" };
        out.push_str(&format!(
            "  [{status}] {} - {}\n",
            result.rule_id, result.reason,
        ));
    }

    Ok(out)
}

fn cmd_hooks_install(path: &Path) -> Result<String> {
    match hooks::install_hook(path) {
        Ok(result) => Ok(format!("{result}\n")),
        Err(e) => anyhow::bail!("{e}"),
    }
}

fn cmd_hooks_uninstall(path: &Path) -> Result<String> {
    match hooks::uninstall_hook(path) {
        Ok(result) => Ok(format!("{result}\n")),
        Err(e) => anyhow::bail!("{e}"),
    }
}

fn cmd_tui(root: &Path, config: &ChaffraConfig) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }

    let host = build_module_host();
    let dead_code_result = host.analyze("dead-code", &files, config)?;
    let mut all_findings = dead_code_result.findings;

    // Also run complexity analysis for more findings.
    if let Ok(complexity_result) = host.analyze("complexity", &files, config) {
        all_findings.extend(complexity_result.findings);
    }

    if all_findings.is_empty() {
        return Ok("No findings to display.\n".to_owned());
    }

    // Run the TUI.
    run_tui(all_findings, root)?;

    Ok(String::new())
}

fn run_tui(findings: Vec<chaffra_core::diagnostic::Finding>, root: &Path) -> Result<()> {
    use crossterm::event::{self, Event, KeyCode};
    use crossterm::terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
    };
    use ratatui::Terminal;
    use ratatui::backend::CrosstermBackend;

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, EnterAlternateScreen)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    let mut app = App::new(findings);

    loop {
        terminal
            .draw(|frame| chaffra_tui::render::render(frame, &app))
            .context("failed to draw frame")?;

        if let Event::Key(key) = event::read().context("failed to read event")? {
            match key.code {
                KeyCode::Char(c) => app.handle_key(c),
                KeyCode::Up => app.move_up(),
                KeyCode::Down => app.move_down(),
                KeyCode::Home => app.move_to_top(),
                KeyCode::End => app.move_to_bottom(),
                KeyCode::Esc => app.quit(),
                _ => {}
            }
        }

        if app.should_quit {
            break;
        }

        // Process pending fix actions.
        let actions: Vec<_> = app.pending_actions.drain(..).collect();
        for action in actions {
            if let chaffra_tui::TuiAction::ApplyFix(idx) = action {
                if idx < app.findings.len() {
                    let finding = &app.findings[idx];
                    let results =
                        chaffra_autofix::orchestrate_fixes(std::slice::from_ref(finding), false)?;
                    if let Some(result) = results.first() {
                        if result.applied {
                            // Apply to disk.
                            let mut file_contents = HashMap::new();
                            for edit in &result.edits {
                                let full_path = root.join(&edit.file);
                                if let Ok(content) = std::fs::read_to_string(&full_path) {
                                    file_contents.insert(edit.file.clone(), content);
                                }
                            }
                            let new_contents =
                                chaffra_autofix::apply_fixes_to_files(&file_contents, &results);
                            for (file, content) in &new_contents {
                                let full_path = root.join(file);
                                std::fs::write(&full_path, content)?;
                            }
                            app.status = format!("Fix applied: {}", result.rule_id);
                        } else {
                            app.status = format!("Fix skipped: {}", result.reason);
                        }
                    }
                }
            }
        }
    }

    disable_raw_mode().context("failed to disable raw mode")?;
    crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")?;

    Ok(())
}

fn cmd_stub(_name: &str) -> String {
    "not yet implemented\n".to_owned()
}

fn cmd_explain(id: &str) -> Result<String> {
    let host = build_module_host();
    let explanation = host.explain(id)?;
    let mut out = String::new();
    out.push_str(&format!(
        "Rule: {} ({})\n",
        explanation.name, explanation.rule_id
    ));
    out.push('\n');
    out.push_str(&explanation.description);
    out.push('\n');
    out.push('\n');
    out.push_str(&format!("Rationale: {}\n", explanation.rationale));
    out.push_str(&format!(
        "Default severity: {}\n",
        explanation.default_severity
    ));
    out.push_str(&format!(
        "Suppress with: {}\n",
        explanation.suppression_syntax
    ));
    if !explanation.examples.is_empty() {
        out.push('\n');
        out.push_str("Examples:\n");
        for example in &explanation.examples {
            out.push_str(&format!("  {example}\n"));
        }
    }
    Ok(out)
}

fn cmd_init(dir: &Path) -> Result<String> {
    let config_path = dir.join(CONFIG_FILE_NAME);
    if config_path.exists() {
        anyhow::bail!("{CONFIG_FILE_NAME} already exists");
    }
    std::fs::write(&config_path, CONFIG_TEMPLATE).context("failed to write configuration file")?;
    Ok(format!("Created {CONFIG_FILE_NAME}\n"))
}

fn cmd_modules() -> String {
    let host = build_module_host();
    let modules = host.list();
    if modules.is_empty() {
        return "No modules registered.\n".to_owned();
    }
    let mut out = String::new();
    for info in modules {
        out.push_str(&format!("{} v{} - {}\n", info.id, info.version, info.name));
        out.push_str(&format!("  Languages: {}\n", info.languages.join(", ")));
        out.push_str(&format!(
            "  Capabilities: {}\n",
            info.capabilities.join(", ")
        ));
        out.push_str(&format!(
            "  Rules: {}\n",
            info.rules
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push('\n');
    }
    out
}

fn cmd_impact(
    root: &Path,
    config: &ChaffraConfig,
    save_path: Option<&str>,
    baseline_path: Option<&str>,
    label: Option<String>,
    format: OutputFormat,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }

    // Run all registered modules and aggregate findings
    let host = build_module_host();
    let mut all_findings: Vec<chaffra_core::diagnostic::Finding> = Vec::new();
    let mut total_files_analyzed: u64 = 0;

    for module_info in host.list() {
        if let Ok(result) = host.analyze(&module_info.id, &files, config) {
            all_findings.extend(result.findings);
            total_files_analyzed = total_files_analyzed.max(result.metrics.files_analyzed);
        }
    }

    let health = chaffra_complexity::analyze_project_health(
        &files,
        config.health.max_cyclomatic,
        config.health.max_cognitive,
    )
    .ok();

    let snapshot = chaffra_impact::snapshot_from_findings(
        &all_findings,
        total_files_analyzed,
        health.as_ref(),
        label,
    );

    // Save snapshot if requested
    if let Some(save_to) = save_path {
        let path = Path::new(save_to);
        chaffra_impact::save_snapshot(&snapshot, path).map_err(|e| anyhow::anyhow!("{}", e))?;
        return Ok(format!("Snapshot saved to {save_to}\n"));
    }

    // Compare against baseline if provided
    if let Some(base_path) = baseline_path {
        let baseline = chaffra_impact::load_snapshot(Path::new(base_path))
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        let report = chaffra_impact::compare_snapshots(&baseline, &snapshot);

        return match format {
            OutputFormat::Json => Ok(chaffra_impact::format_trend_json(&report)),
            _ => Ok(chaffra_impact::format_trend_table(&report)),
        };
    }

    // No baseline: just show current snapshot
    let json = serde_json::to_string_pretty(&snapshot)?;
    Ok(json)
}

fn cmd_migrate(tool_name: &str, project_dir: &Path, write: bool) -> Result<String> {
    let tool = chaffra_migrate::SourceTool::from_str_loose(tool_name)
        .ok_or_else(|| anyhow::anyhow!("unsupported tool: {tool_name}"))?;

    let result =
        chaffra_migrate::migrate(tool, project_dir).map_err(|e| anyhow::anyhow!("{}", e))?;

    if write {
        let config_path = project_dir.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            anyhow::bail!("{CONFIG_FILE_NAME} already exists; remove it first or migrate manually");
        }
        std::fs::write(&config_path, &result.toml_content)
            .context("failed to write configuration file")?;
    }

    let mut out = String::new();

    if write {
        out.push_str(&format!("Wrote {CONFIG_FILE_NAME}\n"));
    } else {
        out.push_str(&result.toml_content);
        out.push('\n');
    }

    if !result.notes.is_empty() {
        out.push('\n');
        out.push_str("Migration notes:\n");
        for note in &result.notes {
            out.push_str(&format!("  - {note}\n"));
        }
    }

    Ok(out)
}

fn cmd_workspaces(root: &Path, format: OutputFormat) -> String {
    let workspaces = chaffra_monorepo::detect_workspaces(root);

    if workspaces.is_empty() {
        return "No workspace configurations detected.\n".to_owned();
    }

    match format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(&workspaces).unwrap_or_else(|_| "[]".to_owned())
        }
        _ => {
            let mut out = String::new();
            for ws in &workspaces {
                out.push_str(&format!(
                    "Workspace: {} ({} members)\n",
                    ws.kind,
                    ws.members.len()
                ));
                for member in &ws.members {
                    out.push_str(&format!("  {} -> {}\n", member.name, member.path.display()));
                }
                out.push('\n');
            }
            out
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let format = OutputFormat::from_str_loose(&cli.format).unwrap_or(OutputFormat::Terminal);
    let formatter = create_formatter(format);

    match cli.command {
        Command::Health { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!("{}", cmd_health(&root, &config, formatter.as_ref())?);
        }

        Command::DeadCode { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!("{}", cmd_dead_code(&root, &config, formatter.as_ref())?);
        }

        Command::Security { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!("{}", cmd_security(&root, &config, formatter.as_ref())?);
        }

        Command::Dupes { .. } => {
            print!("{}", cmd_stub("dupes"));
        }

        Command::Audit { .. } => {
            print!("{}", cmd_stub("audit"));
        }

        Command::Watch { .. } => {
            print!("{}", cmd_stub("watch"));
        }

        Command::Fix {
            path,
            dry_run,
            rule,
        } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!("{}", cmd_fix(&root, &config, dry_run, rule.as_deref())?);
        }

        Command::Hooks { action } => match action {
            HooksAction::Install { path } => {
                let root = Path::new(&path).canonicalize().context("invalid path")?;
                match cmd_hooks_install(&root) {
                    Ok(output) => print!("{output}"),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            HooksAction::Uninstall { path } => {
                let root = Path::new(&path).canonicalize().context("invalid path")?;
                match cmd_hooks_uninstall(&root) {
                    Ok(output) => print!("{output}"),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Command::Tui { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            let output = cmd_tui(&root, &config)?;
            if !output.is_empty() {
                print!("{output}");
            }
        }

        Command::Explain { id } => match cmd_explain(&id) {
            Ok(output) => print!("{output}"),
            Err(e) => {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
        },

        Command::Init => {
            let cwd = std::env::current_dir().context("cannot determine working directory")?;
            match cmd_init(&cwd) {
                Ok(output) => print!("{output}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Modules => {
            print!("{}", cmd_modules());
        }

        Command::Impact {
            path,
            save_snapshot,
            baseline,
            label,
        } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                cmd_impact(
                    &root,
                    &config,
                    save_snapshot.as_deref(),
                    baseline.as_deref(),
                    label,
                    format,
                )?
            );
        }

        Command::Migrate { from, path, write } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            match cmd_migrate(&from, &root, write) {
                Ok(output) => print!("{output}"),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Workspaces { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            print!("{}", cmd_workspaces(&root, format));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_build_module_host() {
        let host = build_module_host();
        let modules = host.list();
        assert_eq!(modules.len(), 5);
        let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"dead-code"));
        assert!(ids.contains(&"complexity"));
        assert!(ids.contains(&"security"));
        assert!(ids.contains(&"frameworks"));
        assert!(ids.contains(&"autofix"));
    }

    #[test]
    fn test_load_config_default() {
        let dir = TempDir::new().unwrap();
        let config = load_config(None, dir.path()).unwrap();
        assert_eq!(config.health.max_cyclomatic, 20);
    }

    #[test]
    fn test_load_config_from_file() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".chaffra.toml");
        fs::write(
            &config_path,
            "[project]\nentry = []\n\n[health]\nmax-cyclomatic = 30\n",
        )
        .unwrap();
        let config = load_config(Some(config_path.to_str().unwrap()), dir.path()).unwrap();
        assert_eq!(config.health.max_cyclomatic, 30);
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_config(Some("/nonexistent/.chaffra.toml"), Path::new("."));
        assert!(result.is_err());
    }

    #[test]
    fn test_discover_and_read_files() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let files = discover_and_read_files(&root, &config);
        assert!(!files.is_empty());
        assert!(files.iter().any(|f| f.path.ends_with(".go")));
    }

    // --- cmd_health tests ---

    #[test]
    fn test_cmd_health_go_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_health(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
        assert!(
            output.contains("Health") || output.contains("Score") || output.contains("Grade"),
            "health output should contain score info: {output}"
        );
    }

    #[test]
    fn test_cmd_health_python_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/python/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Json);
        let output = cmd_health(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_health_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_health(dir.path(), &config, formatter.as_ref()).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    // --- cmd_dead_code tests ---

    #[test]
    fn test_cmd_dead_code_go_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_dead_code(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
        assert!(
            output.contains("unused"),
            "dead-code output should mention 'unused': {output}"
        );
    }

    #[test]
    fn test_cmd_dead_code_python_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/python/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_dead_code(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_dead_code_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_dead_code(dir.path(), &config, formatter.as_ref()).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    #[test]
    fn test_cmd_dead_code_json_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Json);
        let output = cmd_dead_code(&root, &config, formatter.as_ref()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output)
            .unwrap_or_else(|e| panic!("invalid JSON output: {e}\n{output}"));
        assert!(parsed.is_array() || parsed.is_object());
    }

    #[test]
    fn test_cmd_dead_code_markdown_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Markdown);
        let output = cmd_dead_code(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
    }

    // --- stub commands ---

    #[test]
    fn test_cmd_stub_dupes() {
        assert_eq!(cmd_stub("dupes"), "not yet implemented\n");
    }

    #[test]
    fn test_cmd_stub_audit() {
        assert_eq!(cmd_stub("audit"), "not yet implemented\n");
    }

    #[test]
    fn test_cmd_stub_watch() {
        assert_eq!(cmd_stub("watch"), "not yet implemented\n");
    }

    // --- cmd_fix tests ---

    #[test]
    fn test_cmd_fix_dry_run() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let output = cmd_fix(&root, &config, true, None).unwrap();
        assert!(output.contains("Dry run") || output.contains("No auto-fixable"));
    }

    #[test]
    fn test_cmd_fix_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let output = cmd_fix(dir.path(), &config, true, None).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    #[test]
    fn test_cmd_fix_with_rule_filter() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let output = cmd_fix(&root, &config, true, Some("unused-function")).unwrap();
        // Should either find fixable findings or report none.
        assert!(
            output.contains("Dry run") || output.contains("No auto-fixable"),
            "unexpected output: {output}"
        );
    }

    #[test]
    fn test_cmd_fix_with_nonexistent_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let output = cmd_fix(&root, &config, true, Some("nonexistent-rule")).unwrap();
        assert_eq!(output, "No auto-fixable findings.\n");
    }

    // --- cmd_hooks tests ---

    #[test]
    fn test_cmd_hooks_install() {
        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let output = cmd_hooks_install(dir.path()).unwrap();
        assert!(output.contains("installed"));
    }

    #[test]
    fn test_cmd_hooks_install_no_git() {
        let dir = TempDir::new().unwrap();
        let result = cmd_hooks_install(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_hooks_uninstall() {
        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        // Install first, then uninstall.
        hooks::install_hook(dir.path()).unwrap();
        let output = cmd_hooks_uninstall(dir.path()).unwrap();
        assert!(output.contains("uninstalled") || output.contains("Uninstalled"));
    }

    #[test]
    fn test_cmd_hooks_uninstall_not_installed() {
        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let output = cmd_hooks_uninstall(dir.path()).unwrap();
        assert!(output.contains("No chaffra") || output.contains("not found"));
    }

    // --- cmd_explain tests ---

    #[test]
    fn test_cmd_explain_unused_function() {
        let output = cmd_explain("dead-code:unused-function").unwrap();
        assert!(output.contains("Unused function"));
        assert!(output.contains("Rationale:"));
        assert!(output.contains("Default severity:"));
        assert!(output.contains("Suppress with:"));
        assert!(output.contains("Examples:"));
    }

    #[test]
    fn test_cmd_explain_high_cyclomatic() {
        let output = cmd_explain("complexity:high-cyclomatic").unwrap();
        assert!(output.contains("High cyclomatic complexity"));
        assert!(output.contains("Rationale:"));
    }

    #[test]
    fn test_cmd_explain_autofix_rule() {
        let output = cmd_explain("autofix:fix-conflict").unwrap();
        assert!(output.contains("Fix conflict"));
        assert!(output.contains("overlapping"));
    }

    #[test]
    fn test_cmd_explain_unknown_rule() {
        let result = cmd_explain("dead-code:nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_explain_unknown_module() {
        let result = cmd_explain("bogus:rule");
        assert!(result.is_err());
    }

    // --- cmd_init tests ---

    #[test]
    fn test_cmd_init_creates_file() {
        let dir = TempDir::new().unwrap();
        let output = cmd_init(dir.path()).unwrap();
        assert!(output.contains("Created"));
        let config_path = dir.path().join(CONFIG_FILE_NAME);
        assert!(config_path.exists());
        let contents = fs::read_to_string(&config_path).unwrap();
        assert!(contents.contains("[project]"));
    }

    #[test]
    fn test_cmd_init_already_exists() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILE_NAME), "existing").unwrap();
        let result = cmd_init(dir.path());
        assert!(result.is_err());
    }

    // --- cmd_modules tests ---

    #[test]
    fn test_cmd_modules_lists_registered() {
        let output = cmd_modules();
        assert!(output.contains("dead-code"), "should list dead-code module");
        assert!(
            output.contains("complexity"),
            "should list complexity module"
        );
        assert!(output.contains("security"), "should list security module");
        assert!(
            output.contains("frameworks"),
            "should list frameworks module"
        );
        assert!(output.contains("autofix"), "should list autofix module");
        assert!(output.contains("Languages:"));
        assert!(output.contains("Capabilities:"));
        assert!(output.contains("Rules:"));
    }

    // --- cmd_security tests ---

    #[test]
    fn test_cmd_security_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_security(dir.path(), &config, formatter.as_ref()).unwrap();
        assert_eq!(output, "No files found.\n");
    }

    #[test]
    fn test_cmd_security_with_fixtures() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/security/vulnerable");
        if root.exists() {
            let config = ChaffraConfig::default();
            let formatter = create_formatter(OutputFormat::Terminal);
            let output = cmd_security(&root, &config, formatter.as_ref()).unwrap();
            assert!(!output.is_empty());
        }
    }

    #[test]
    fn test_cmd_security_json_format() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/security/vulnerable");
        if root.exists() {
            let config = ChaffraConfig::default();
            let formatter = create_formatter(OutputFormat::Json);
            let output = cmd_security(&root, &config, formatter.as_ref()).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&output)
                .unwrap_or_else(|e| panic!("invalid JSON output: {e}\n{output}"));
            assert!(parsed.is_array() || parsed.is_object());
        }
    }

    #[test]
    fn test_cmd_security_clean_handler_no_false_positive() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/security/clean");
        if root.exists() {
            let config = ChaffraConfig::default();
            let formatter = create_formatter(OutputFormat::Terminal);
            let output = cmd_security(&root, &config, formatter.as_ref()).unwrap();
            assert!(
                !output.contains("sql-injection")
                    && !output.contains("command-injection")
                    && !output.contains("xss")
                    && !output.contains("ssrf")
                    && !output.contains("path-traversal"),
                "clean handlers should not produce SAST findings, got: {output}"
            );
        }
    }

    #[test]
    fn test_cmd_security_discovers_nested_manifests() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/security/nested");
        if root.exists() {
            let config = ChaffraConfig::default();
            let formatter = create_formatter(OutputFormat::Terminal);
            let output = cmd_security(&root, &config, formatter.as_ref()).unwrap();
            assert!(
                !output.is_empty(),
                "should discover files in nested directories"
            );
        }
    }

    #[test]
    fn test_cmd_security_discovers_dotenv_files() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".env"),
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDB_PASSWORD=supersecret123\n",
        )
        .unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_security(dir.path(), &config, formatter.as_ref()).unwrap();
        assert!(
            output.contains("hardcoded-secret") || output.contains("high-entropy"),
            "should detect secrets in .env files, got: {output}"
        );
    }

    #[test]
    fn test_cmd_explain_sql_injection() {
        let output = cmd_explain("security:sql-injection").unwrap();
        assert!(output.contains("SQL injection"));
        assert!(output.contains("Rationale:"));
        assert!(output.contains("Examples:"));
    }

    #[test]
    fn test_cmd_explain_hardcoded_secret() {
        let output = cmd_explain("security:hardcoded-secret").unwrap();
        assert!(output.contains("Hardcoded secret"));
        assert!(output.contains("Rationale:"));
    }

    #[test]
    fn test_cmd_explain_vulnerable_dependency() {
        let output = cmd_explain("security:vulnerable-dependency").unwrap();
        assert!(output.contains("Vulnerable dependency"));
        assert!(output.contains("Rationale:"));
    }

    // --- cmd_impact tests ---

    #[test]
    fn test_cmd_impact_save_snapshot() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("snapshot.json");

        let output = cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            Some("test-label".to_owned()),
            OutputFormat::Terminal,
        )
        .unwrap();
        assert!(output.contains("Snapshot saved"));
        assert!(snapshot_path.exists());

        let content = fs::read_to_string(&snapshot_path).unwrap();
        let snapshot: chaffra_impact::Snapshot = serde_json::from_str(&content).unwrap();
        assert_eq!(snapshot.label, Some("test-label".to_owned()));
    }

    #[test]
    fn test_cmd_impact_compare_snapshots() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("baseline.json");

        cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            Some("baseline".to_owned()),
            OutputFormat::Terminal,
        )
        .unwrap();

        let output = cmd_impact(
            &root,
            &config,
            None,
            Some(snapshot_path.to_str().unwrap()),
            Some("current".to_owned()),
            OutputFormat::Terminal,
        )
        .unwrap();

        assert!(output.contains("Impact Report"));
        assert!(output.contains("Catch Rate"));
    }

    #[test]
    fn test_cmd_impact_compare_json_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("baseline.json");

        cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            None,
            OutputFormat::Terminal,
        )
        .unwrap();

        let output = cmd_impact(
            &root,
            &config,
            None,
            Some(snapshot_path.to_str().unwrap()),
            None,
            OutputFormat::Json,
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.get("trends").is_some());
        assert!(parsed.get("catch_rate").is_some());
    }

    #[test]
    fn test_cmd_impact_no_files() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let output = cmd_impact(
            dir.path(),
            &config,
            None,
            None,
            None,
            OutputFormat::Terminal,
        )
        .unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    // --- cmd_migrate tests ---

    #[test]
    fn test_cmd_migrate_knip() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("knip.json"),
            r#"{"entry": ["src/index.ts"], "ignore": ["dist/**"]}"#,
        )
        .unwrap();

        let output = cmd_migrate("knip", dir.path(), false).unwrap();
        assert!(output.contains("[project]"));
        assert!(output.contains("src/index.ts"));
    }

    #[test]
    fn test_cmd_migrate_write() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("knip.json"),
            r#"{"entry": ["src/index.ts"]}"#,
        )
        .unwrap();

        let output = cmd_migrate("knip", dir.path(), true).unwrap();
        assert!(output.contains("Wrote"));
        assert!(dir.path().join(CONFIG_FILE_NAME).exists());
    }

    #[test]
    fn test_cmd_migrate_write_exists() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(CONFIG_FILE_NAME), "existing").unwrap();
        fs::write(dir.path().join("knip.json"), r#"{"entry": []}"#).unwrap();

        let result = cmd_migrate("knip", dir.path(), true);
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_migrate_unknown_tool() {
        let dir = TempDir::new().unwrap();
        let result = cmd_migrate("unknown-tool", dir.path(), false);
        assert!(result.is_err());
    }

    // --- cmd_workspaces tests ---

    #[test]
    fn test_cmd_workspaces_empty() {
        let dir = TempDir::new().unwrap();
        let output = cmd_workspaces(dir.path(), OutputFormat::Terminal);
        assert!(output.contains("No workspace"));
    }

    #[test]
    fn test_cmd_workspaces_rust() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("crates/core")).unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/core\"]\n",
        )
        .unwrap();

        let output = cmd_workspaces(dir.path(), OutputFormat::Terminal);
        assert!(output.contains("rust-cargo"));
        assert!(output.contains("core"));
    }

    #[test]
    fn test_cmd_workspaces_json() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("crates/a")).unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/a\"]\n",
        )
        .unwrap();

        let output = cmd_workspaces(dir.path(), OutputFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn test_cmd_workspaces_go() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("go.work"),
            "go 1.21\n\nuse (\n\t./svc-a\n\t./svc-b\n)\n",
        )
        .unwrap();

        let output = cmd_workspaces(dir.path(), OutputFormat::Terminal);
        assert!(output.contains("go-work"));
        assert!(output.contains("svc-a"));
    }

    #[test]
    fn test_cmd_workspaces_js() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("packages/ui")).unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "root", "workspaces": ["packages/ui"]}"#,
        )
        .unwrap();

        let output = cmd_workspaces(dir.path(), OutputFormat::Terminal);
        assert!(output.contains("js-package-json"));
        assert!(output.contains("ui"));
    }

    // --- P1-1 regression: workspace flags removed until wired ---

    #[test]
    fn test_cli_struct_has_no_group_by_field() {
        // Ensure --group-by and --changed-workspaces are not accepted
        // until they are properly wired into analysis commands.
        let result = Cli::try_parse_from(["chaffra", "--group-by", "workspace", "health"]);
        assert!(
            result.is_err(),
            "unexpected --group-by flag should be rejected"
        );
    }

    #[test]
    fn test_cli_struct_has_no_changed_workspaces_field() {
        let result = Cli::try_parse_from(["chaffra", "--changed-workspaces", "main", "health"]);
        assert!(
            result.is_err(),
            "unexpected --changed-workspaces flag should be rejected"
        );
    }

    // --- P1-2 regression: impact aggregates all modules ---

    #[test]
    fn test_cmd_impact_aggregates_all_modules() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("snapshot.json");

        cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            Some("all-modules".to_owned()),
            OutputFormat::Terminal,
        )
        .unwrap();

        let content = fs::read_to_string(&snapshot_path).unwrap();
        let snapshot: chaffra_impact::Snapshot = serde_json::from_str(&content).unwrap();

        // The snapshot must contain findings from dead-code AND complexity
        // modules, not just dead-code alone.
        let has_dead_code = snapshot
            .finding_counts
            .keys()
            .any(|k| k.starts_with("unused-") || k.starts_with("dead-"));
        let has_complexity = snapshot
            .finding_counts
            .keys()
            .any(|k| k.starts_with("high-"));

        assert!(
            has_dead_code || has_complexity,
            "snapshot should aggregate findings from multiple modules, got keys: {:?}",
            snapshot.finding_counts.keys().collect::<Vec<_>>()
        );

        // total_findings should reflect all modules' findings combined
        let total = snapshot
            .metrics
            .get("total_findings")
            .copied()
            .unwrap_or(0.0);
        let sum_by_rule: u64 = snapshot.finding_counts.values().sum();
        assert_eq!(
            total as u64, sum_by_rule,
            "total_findings metric should equal sum of all finding_counts"
        );
    }

    // --- cmd_tui tests (non-interactive only) ---

    #[test]
    fn test_cmd_tui_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let output = cmd_tui(dir.path(), &config).unwrap();
        assert_eq!(output, "No source files found.\n");
    }
}
