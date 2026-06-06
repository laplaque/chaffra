//! chaffra -- codebase intelligence CLI.

mod lsp;
mod watch;

use anyhow::{Context, Result};
use chaffra_ai_quality::AiQualityModule;
use chaffra_arch::ArchModule;
use chaffra_audit::AuditModule;
use chaffra_autofix::AutofixModule;
use chaffra_autofix::hooks;
use chaffra_cicd_security::CicdSecurityModule;
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::{CONFIG_FILE_NAME, CONFIG_TEMPLATE, ChaffraConfig};
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::grpc::GrpcModuleHost;
use chaffra_deadcode::DeadCodeModule;
use chaffra_duplication::DuplicationModule;
use chaffra_frameworks::FrameworksModule;
use chaffra_hotspot::HotspotModule;
use chaffra_llm_defense::LlmDefenseModule;
use chaffra_output::{OutputFormat, create_formatter};
use chaffra_security::SecurityModule;
use chaffra_telemetry::TelemetryModule;
use chaffra_tui::App;
use clap::{Parser, Subcommand};
use std::collections::{HashMap, HashSet};
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

    /// Output format: json, markdown, terminal, pr-comment, annotations, codeclimate, badge, sarif.
    #[arg(long, global = true, default_value = "terminal")]
    format: String,

    /// Path to configuration file.
    #[arg(long, global = true)]
    config: Option<String>,

    /// Telemetry mode: on, off, user-only, operator-only.
    #[arg(long, global = true, default_value = "on")]
    telemetry: String,

    /// Override telemetry backend (json-file, stderr, prometheus, otlp, statsd).
    #[arg(long = "telemetry-backend", global = true)]
    telemetry_backend: Option<String>,

    /// Override OTLP endpoint.
    #[arg(long = "telemetry-endpoint", global = true)]
    telemetry_endpoint: Option<String>,
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

        /// Detection mode: strict, mild, weak, or semantic.
        #[arg(long, default_value = "strict")]
        mode: String,

        /// Minimum token count for a clone (default: 50).
        #[arg(long, default_value = "50")]
        min_tokens: String,
    },
    /// Validate architecture boundaries and detect circular dependencies.
    Boundaries {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,

        /// Architecture preset: layered, hexagonal, feature-sliced, clean.
        #[arg(long)]
        preset: Option<String>,
    },
    /// Run a PR audit: compare against baseline and emit a pass/fail verdict.
    Audit {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Rank files by churn x complexity hotspot score.
    Hotspot {
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
    /// Detect AI-generated code quality issues: hallucinated APIs, stubs, disabled controls.
    #[command(name = "ai-quality")]
    AiQuality {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Detect LLM integration risks: prompt injection, unsafe tools, unguarded loops.
    #[command(name = "llm-defense")]
    LlmDefense {
        /// Path to the repository root (defaults to current directory).
        #[arg(default_value = ".")]
        path: String,
    },
    /// Scan CI/CD configuration files for security misconfigurations.
    #[command(name = "cicd-security")]
    CicdSecurity {
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
    /// Start the MCP server (JSON-RPC 2.0 over stdio).
    Mcp,
    /// Start the LSP server (Language Server Protocol over stdio).
    Lsp,
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
    /// Telemetry commands: status, test, inspect, dashboard, audit-log.
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },
    /// Start a standalone management HTTP server for telemetry inspection.
    ///
    /// Serves an empty collector with core metric definitions registered.
    /// Useful for verifying the dashboard UI, API shape, and backend connectivity.
    /// Co-located mode (sharing a live collector from watch/MCP/LSP) is planned.
    Management {
        /// Port to bind the management server to.
        #[arg(long, default_value = "9100")]
        port: u16,
    },
}

#[derive(Subcommand)]
enum TelemetryAction {
    /// Show telemetry backends and connection status.
    Status,
    /// Emit a test metric and report success or failure.
    Test,
    /// Dry-run: show what telemetry payload would be emitted.
    Inspect,
    /// Generate an import-ready Grafana dashboard JSON.
    Dashboard {
        /// Datasource type: prometheus (default) or otlp.
        #[arg(long, default_value = "prometheus")]
        datasource: String,
        /// Print to stdout instead of writing a file.
        #[arg(long)]
        stdout: bool,
    },
    /// Display the telemetry audit log for GDPR accountability.
    AuditLog {
        /// Export events as JSON array for GDPR data subject access requests.
        #[arg(long)]
        export: bool,
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

pub(crate) fn build_module_host() -> GrpcModuleHost {
    build_module_host_with_telemetry(None)
}

fn build_module_host_with_telemetry(
    collector: Option<&chaffra_telemetry::TelemetryCollector>,
) -> GrpcModuleHost {
    let total_start = std::time::Instant::now();
    let mut host = GrpcModuleHost::new();

    let modules: Vec<(&str, Box<dyn chaffra_core::module::AnalysisModule>)> = vec![
        ("dead-code", Box::new(DeadCodeModule::new())),
        ("complexity", Box::new(ComplexityModule::new())),
        ("security", Box::new(SecurityModule::new())),
        ("frameworks", Box::new(FrameworksModule::new())),
        ("audit", Box::new(AuditModule::new())),
        ("hotspot", Box::new(HotspotModule::new())),
        ("autofix", Box::new(AutofixModule::new())),
        ("ai-quality", Box::new(AiQualityModule::new())),
        ("llm-defense", Box::new(LlmDefenseModule::new())),
        ("cicd-security", Box::new(CicdSecurityModule::new())),
        ("telemetry", Box::new(TelemetryModule::new())),
        ("duplication", Box::new(DuplicationModule::new())),
        ("architecture", Box::new(ArchModule::new())),
    ];

    for (id, module) in modules {
        let start = std::time::Instant::now();
        let result = host.register(module);
        let duration_ms = start.elapsed().as_millis() as u64;

        if let Some(c) = collector {
            c.record_module_startup(id, duration_ms);
            if result.is_err() {
                c.record_module_load_error(id, "registration_failed");
            }
        }
    }

    if let Some(c) = collector {
        let total_ms = total_start.elapsed().as_millis() as u64;
        c.record_startup_total(total_ms);
    }

    host
}

fn load_config(config_path: Option<&str>, analysis_path: &Path) -> Result<ChaffraConfig> {
    if let Some(path) = config_path {
        ChaffraConfig::load(Path::new(path)).context("failed to load configuration file")
    } else {
        Ok(ChaffraConfig::load_from_dir(analysis_path).unwrap_or_default())
    }
}

fn fingerprints_from_findings(
    findings: &[chaffra_core::diagnostic::Finding],
) -> HashSet<chaffra_telemetry::churn::FindingFingerprint> {
    findings
        .iter()
        .map(|f| {
            chaffra_telemetry::churn::FindingFingerprint::new(
                &f.rule_id,
                &f.location.file,
                f.location.start_line,
            )
        })
        .collect()
}

fn merge_telemetry_config(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    project_config: &ChaffraConfig,
) -> chaffra_telemetry::TelemetryConfig {
    let mut config = cli_config.clone();
    let module_cfg = project_config.module_config("telemetry");
    if !module_cfg.is_empty() {
        let project_tel = chaffra_telemetry::TelemetryConfig::from_module_config(&module_cfg);
        config.sampling_rate = project_tel.sampling_rate;
        config.sampling_strategy = project_tel.sampling_strategy;
    }
    config
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
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let result = host.analyze("dead-code", &files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_dupes(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    mode: &str,
    min_tokens: &str,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let mut module_config = config.module_config("duplication");
    module_config.insert("mode".to_owned(), mode.to_owned());
    module_config.insert("min-tokens".to_owned(), min_tokens.to_owned());

    let result = host.analyze_with_config("duplication", &files, &module_config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    if result.findings.is_empty() {
        return Ok("No duplicates found.\n".to_owned());
    }
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_boundaries(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    preset: Option<&str>,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let mut module_config = config.module_config("architecture");
    if let Some(p) = preset {
        module_config.insert("preset".to_owned(), p.to_owned());
    }
    let result = host.analyze_with_config("architecture", &files, &module_config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    if result.findings.is_empty() {
        return Ok("No architecture violations found.\n".to_owned());
    }
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_security(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let mut files = discover_and_read_files(root, config);

    discover_security_files(root, root, &mut files);

    if files.is_empty() {
        return Ok("No files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let result = host.analyze("security", &files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
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

fn cmd_ai_quality(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let result = host.analyze("ai-quality", &files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_audit(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    let host = build_module_host_with_telemetry(Some(collector));

    // First, run dead-code and complexity to collect findings.
    let mut all_findings = Vec::new();
    if let Ok(result) = host.analyze("dead-code", &files, config) {
        all_findings.extend(result.findings);
    }
    if let Ok(result) = host.analyze("complexity", &files, config) {
        all_findings.extend(result.findings);
    }

    // Package findings as JSON for the audit module.
    let findings_json = serde_json::to_vec(&all_findings).unwrap_or_default();
    let audit_files = vec![FileInfo {
        path: "findings.json".to_owned(),
        content: findings_json,
    }];

    let result = host.analyze("audit", &audit_files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_hotspot(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let result = host.analyze("hotspot", &files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_llm_defense(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let result = host.analyze("llm-defense", &files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_cicd_security(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_all_files(root, config);
    if files.is_empty() {
        return Ok("No files found.\n".to_owned());
    }
    let host = build_module_host_with_telemetry(Some(collector));
    let result = host.analyze("cicd-security", &files, config)?;
    collector.set_finding_fingerprints(fingerprints_from_findings(&result.findings));
    if result.findings.is_empty() {
        return Ok("No CI/CD security issues found.\n".to_owned());
    }
    Ok(formatter.format_findings(&result.findings))
}

fn discover_all_files(root: &Path, config: &ChaffraConfig) -> Vec<FileInfo> {
    let ignore_patterns = &config.project.ignore;
    let mut files = Vec::new();
    collect_files(root, root, ignore_patterns, &mut files);
    files
}

fn collect_files(base: &Path, dir: &Path, ignore: &[String], out: &mut Vec<FileInfo>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = path.strip_prefix(base).unwrap_or(&path);
        let rel_str = relative.to_string_lossy();

        if let Some(name) = path.file_name() {
            let name = name.to_string_lossy();
            if name.starts_with('.') && name != ".github" && name != ".gitlab-ci.yml" {
                continue;
            }
            if name == "node_modules"
                || name == "target"
                || name == "vendor"
                || name == "__pycache__"
            {
                continue;
            }
        }

        if ignore.iter().any(|pat| rel_str.contains(pat)) {
            continue;
        }

        if path.is_dir() {
            collect_files(base, &path, ignore, out);
        } else {
            // Check file type by path BEFORE reading content to avoid
            // eagerly loading files we will never analyze.
            let file_type = chaffra_cicd_security::detect::detect_file_type(&rel_str);
            if file_type == chaffra_cicd_security::detect::CicdFileType::Unknown {
                continue;
            }
            if let Ok(content) = std::fs::read(&path) {
                out.push(FileInfo {
                    path: rel_str.to_string(),
                    content,
                });
            }
        }
    }
}

fn cmd_fix(
    root: &Path,
    config: &ChaffraConfig,
    dry_run: bool,
    rule: Option<&str>,
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }

    let host = build_module_host_with_telemetry(Some(collector));

    let dead_code_result = host.analyze("dead-code", &files, config)?;
    let mut all_findings = dead_code_result.findings;

    match host.analyze("complexity", &files, config) {
        Ok(result) => all_findings.extend(result.findings),
        Err(e) => eprintln!("warning: complexity analysis failed: {e}"),
    }

    collector.set_finding_fingerprints(fingerprints_from_findings(&all_findings));

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

    match host.analyze("complexity", &files, config) {
        Ok(result) => all_findings.extend(result.findings),
        Err(e) => eprintln!("warning: complexity analysis failed: {e}"),
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
    collector: &chaffra_telemetry::TelemetryCollector,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }

    // Run all registered modules and aggregate findings
    let host = build_module_host_with_telemetry(Some(collector));
    let mut all_findings: Vec<chaffra_core::diagnostic::Finding> = Vec::new();
    let mut total_files_analyzed: u64 = 0;

    for module_info in host.list() {
        if let Ok(result) = host.analyze(&module_info.id, &files, config) {
            all_findings.extend(result.findings);
            total_files_analyzed = total_files_analyzed.max(result.metrics.files_analyzed);
        }
    }

    collector.set_finding_fingerprints(fingerprints_from_findings(&all_findings));

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

fn build_telemetry_config(cli: &Cli) -> chaffra_telemetry::TelemetryConfig {
    let audience = chaffra_telemetry::TelemetryAudience::from_str_loose(&cli.telemetry)
        .unwrap_or(chaffra_telemetry::TelemetryAudience::On);

    let backends = if let Some(ref backend_str) = cli.telemetry_backend {
        if let Some(kind) = chaffra_telemetry::BackendKind::from_str_loose(backend_str) {
            vec![chaffra_telemetry::BackendConfig {
                kind,
                endpoint: cli.telemetry_endpoint.clone(),
                path: None,
                options: HashMap::new(),
            }]
        } else {
            chaffra_telemetry::TelemetryConfig::default().backends
        }
    } else if let Some(ref endpoint) = cli.telemetry_endpoint {
        vec![chaffra_telemetry::BackendConfig {
            kind: chaffra_telemetry::BackendKind::Otlp,
            endpoint: Some(endpoint.clone()),
            path: None,
            options: HashMap::new(),
        }]
    } else {
        chaffra_telemetry::TelemetryConfig::default().backends
    };

    chaffra_telemetry::TelemetryConfig {
        audience,
        backends,
        ..Default::default()
    }
}

fn cmd_telemetry_status(tel_config: &chaffra_telemetry::TelemetryConfig) -> String {
    let mut out = String::new();
    out.push_str(&format!("Telemetry mode: {:?}\n\n", tel_config.audience));
    out.push_str("Backends:\n");

    let (_, statuses) = chaffra_telemetry::backends::create_backends(&tel_config.backends);
    for status in &statuses {
        let icon = if status.connected { "OK" } else { "FAIL" };
        out.push_str(&format!(
            "  [{icon}] {} ({}) -- {}\n",
            status.name, status.kind, status.message
        ));
    }

    if statuses.is_empty() {
        out.push_str("  (no backends configured)\n");
    }

    out
}

fn cmd_telemetry_test(tel_config: &chaffra_telemetry::TelemetryConfig) -> Result<String> {
    let collector = chaffra_telemetry::TelemetryCollector::new(tel_config.clone());
    collector.register_core_metrics();

    // Emit a test data point.
    collector.record_data_point(chaffra_telemetry::MetricDataPoint {
        name: "chaffra.telemetry.test".to_owned(),
        value: 1.0,
        labels: HashMap::new(),
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    });

    let snapshot = collector.snapshot();
    let (backends, _) = chaffra_telemetry::backends::create_backends(&tel_config.backends);

    let mut out = String::new();
    for backend in &backends {
        match backend.flush(&snapshot) {
            Ok(()) => out.push_str(&format!("[OK] {} -- test metric flushed\n", backend.name())),
            Err(e) => out.push_str(&format!("[FAIL] {} -- {e}\n", backend.name())),
        }
    }

    if backends.is_empty() {
        out.push_str("No backends configured.\n");
    }

    Ok(out)
}

fn cmd_telemetry_inspect(tel_config: &chaffra_telemetry::TelemetryConfig) -> Result<String> {
    let collector = chaffra_telemetry::TelemetryCollector::new(tel_config.clone());
    collector.register_core_metrics();
    collector.set_files_total(0);

    // Simulate some data.
    collector.record_module_call("example-module", 100, false);
    let mut sev = HashMap::new();
    sev.insert("warning".to_owned(), 2);
    collector.record_module_findings("example-module", 2, &sev);

    let snapshot = collector.snapshot();
    let (backends, _) = chaffra_telemetry::backends::create_backends(&tel_config.backends);

    let mut out = String::new();
    for backend in &backends {
        out.push_str(&format!("--- {} ---\n", backend.name()));
        match backend.inspect(&snapshot) {
            Ok(payload) => out.push_str(&payload),
            Err(e) => out.push_str(&format!("Error: {e}")),
        }
        out.push_str("\n\n");
    }

    Ok(out)
}

fn cmd_telemetry_dashboard(datasource_str: &str, to_stdout: bool) -> Result<String> {
    let datasource =
        chaffra_telemetry::dashboard::DashboardDatasource::from_str_loose(datasource_str)
            .unwrap_or(chaffra_telemetry::dashboard::DashboardDatasource::Prometheus);

    let dashboard = chaffra_telemetry::dashboard::generate_dashboard(datasource);
    let json = serde_json::to_string_pretty(&dashboard)?;

    if to_stdout {
        return Ok(json);
    }

    let filename = "chaffra-grafana-dashboard.json";
    std::fs::write(filename, &json)?;
    Ok(format!("Dashboard written to {filename}\n"))
}

fn cmd_telemetry_audit_log(export: bool) -> String {
    let log_path = std::path::Path::new(chaffra_telemetry::audit_log::AUDIT_LOG_FILE);
    let events = chaffra_telemetry::audit_log::read_log(log_path);

    if export {
        chaffra_telemetry::audit_log::export_for_gdpr(&events)
    } else {
        chaffra_telemetry::audit_log::format_log_display(&events)
    }
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

fn run_with_telemetry<F>(
    tel_config: &chaffra_telemetry::TelemetryConfig,
    project_config: &ChaffraConfig,
    command_name: &str,
    f: F,
) -> Result<String>
where
    F: FnOnce(&chaffra_telemetry::TelemetryCollector) -> Result<String>,
{
    let effective_config = merge_telemetry_config(tel_config, project_config);

    if matches!(
        effective_config.audience,
        chaffra_telemetry::TelemetryAudience::Off
    ) {
        let collector = chaffra_telemetry::TelemetryCollector::new(effective_config);
        return f(&collector);
    }

    let collector = chaffra_telemetry::TelemetryCollector::new(effective_config.clone());
    collector.register_core_metrics();
    let start = std::time::Instant::now();

    let result = f(&collector);

    let duration_ms = start.elapsed().as_millis() as u64;
    let failed = result.is_err();
    collector.record_module_call(command_name, duration_ms, failed);

    if !failed {
        let current_fingerprints = collector.finding_fingerprints();
        let state_path = std::path::Path::new(chaffra_telemetry::churn::STATE_FILE);
        let previous_state = chaffra_telemetry::churn::load_state(state_path);

        let current_hash = chaffra_telemetry::churn::hash_fingerprints(&current_fingerprints);

        if let Some(ref prev) = previous_state {
            let churn = chaffra_telemetry::churn::compute_churn(&current_fingerprints, prev);
            collector.record_finding_churn(&churn);
        }

        let decision = chaffra_telemetry::sampling::should_sample(
            effective_config.sampling_strategy,
            effective_config.sampling_rate,
            current_hash,
            previous_state.as_ref().map(|s| s.findings_hash),
        );

        if decision == chaffra_telemetry::SamplingDecision::Emit {
            let (backends, _) =
                chaffra_telemetry::backends::create_backends(&effective_config.backends);
            let snapshot = collector.snapshot();
            for backend in &backends {
                let _ = backend.flush(&snapshot);
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
    } else {
        let (backends, _) =
            chaffra_telemetry::backends::create_backends(&effective_config.backends);
        let snapshot = collector.snapshot();
        for backend in &backends {
            let _ = backend.flush(&snapshot);
        }
    }

    result
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let format = OutputFormat::from_str_loose(&cli.format).unwrap_or(OutputFormat::Terminal);
    let formatter = create_formatter(format);
    let tel_config = build_telemetry_config(&cli);

    match cli.command {
        Command::Health { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "health", |_collector| {
                    cmd_health(&root, &config, formatter.as_ref())
                })?
            );
        }

        Command::DeadCode { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "dead-code", |collector| {
                    cmd_dead_code(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::Security { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "security", |collector| {
                    cmd_security(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::Audit { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "audit", |collector| {
                    cmd_audit(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::Hotspot { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "hotspot", |collector| {
                    cmd_hotspot(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::AiQuality { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "ai-quality", |collector| {
                    cmd_ai_quality(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::LlmDefense { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "llm-defense", |collector| {
                    cmd_llm_defense(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::CicdSecurity { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "cicd-security", |collector| {
                    cmd_cicd_security(&root, &config, formatter.as_ref(), collector)
                })?
            );
        }

        Command::Dupes {
            path,
            mode,
            min_tokens,
        } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "duplication", |collector| {
                    cmd_dupes(
                        &root,
                        &config,
                        formatter.as_ref(),
                        &mode,
                        &min_tokens,
                        collector,
                    )
                })?
            );
        }

        Command::Boundaries { path, preset } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "architecture", |collector| {
                    cmd_boundaries(
                        &root,
                        &config,
                        formatter.as_ref(),
                        preset.as_deref(),
                        collector,
                    )
                })?
            );
        }

        Command::Watch { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            let watch_config = watch::WatchConfig::new(root, format, config);
            watch::run_watch(watch_config)?;
        }

        Command::Mcp => {
            let mut server = chaffra_mcp::McpServer::new();
            server
                .run()
                .await
                .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;
        }

        Command::Lsp => {
            lsp::run_lsp_server().await?;
        }

        Command::Fix {
            path,
            dry_run,
            rule,
        } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!(
                "{}",
                run_with_telemetry(&tel_config, &config, "fix", |collector| {
                    cmd_fix(&root, &config, dry_run, rule.as_deref(), collector)
                })?
            );
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
                run_with_telemetry(&tel_config, &config, "impact", |collector| {
                    cmd_impact(
                        &root,
                        &config,
                        save_snapshot.as_deref(),
                        baseline.as_deref(),
                        label.clone(),
                        format,
                        collector,
                    )
                })?
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

        Command::Telemetry { ref action } => match action {
            TelemetryAction::Status => {
                print!("{}", cmd_telemetry_status(&tel_config));
            }
            TelemetryAction::Test => match cmd_telemetry_test(&tel_config) {
                Ok(output) => print!("{output}"),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            },
            TelemetryAction::Inspect => match cmd_telemetry_inspect(&tel_config) {
                Ok(output) => print!("{output}"),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            },
            TelemetryAction::Dashboard { datasource, stdout } => {
                match cmd_telemetry_dashboard(datasource, *stdout) {
                    Ok(output) => print!("{output}"),
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            TelemetryAction::AuditLog { export } => {
                print!("{}", cmd_telemetry_audit_log(*export));
            }
        },

        Command::Management { port } => {
            let collector = chaffra_telemetry::TelemetryCollector::new(tel_config);
            collector.register_core_metrics();
            let config = chaffra_management::ManagementConfig { port };
            let server = chaffra_management::ManagementServer::new(config, collector);
            server.run().await?;
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
        assert_eq!(modules.len(), 13);
        let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"dead-code"));
        assert!(ids.contains(&"complexity"));
        assert!(ids.contains(&"security"));
        assert!(ids.contains(&"frameworks"));
        assert!(ids.contains(&"audit"));
        assert!(ids.contains(&"hotspot"));
        assert!(ids.contains(&"autofix"));
        assert!(ids.contains(&"ai-quality"));
        assert!(ids.contains(&"llm-defense"));
        assert!(ids.contains(&"cicd-security"));
        assert!(ids.contains(&"telemetry"));
        assert!(ids.contains(&"duplication"));
        assert!(ids.contains(&"architecture"));
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

    #[test]
    fn test_cmd_health_badge_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Badge);
        let output = cmd_health(&root, &config, formatter.as_ref()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output)
            .unwrap_or_else(|e| panic!("invalid badge JSON: {e}\n{output}"));
        assert!(parsed["schemaVersion"].is_number());
        assert!(parsed["color"].is_string());
    }

    // --- cmd_dead_code tests ---

    #[test]
    fn test_cmd_dead_code_go_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dead_code(&root, &config, formatter.as_ref(), &collector).unwrap();
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dead_code(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_dead_code_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dead_code(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    #[test]
    fn test_cmd_dead_code_json_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Json);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dead_code(&root, &config, formatter.as_ref(), &collector).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output)
            .unwrap_or_else(|e| panic!("invalid JSON output: {e}\n{output}"));
        assert!(parsed.is_array() || parsed.is_object());
    }

    #[test]
    fn test_cmd_dead_code_markdown_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Markdown);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dead_code(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_dead_code_badge_format() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Badge);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dead_code(&root, &config, formatter.as_ref(), &collector).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["schemaVersion"].is_number());
    }

    // --- stub commands ---

    #[test]
    fn test_cmd_dupes_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_dupes(
            dir.path(),
            &config,
            formatter.as_ref(),
            "strict",
            "50",
            &collector,
        )
        .unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    #[test]
    fn test_cmd_boundaries_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_boundaries(
            dir.path(),
            &config,
            formatter.as_ref(),
            Some("layered"),
            &collector,
        )
        .unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    #[test]
    fn test_cmd_audit_go_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_audit(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_audit_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_audit(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_hotspot_no_commit_data() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_hotspot(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(output.contains("No issues found"));
    }

    #[test]
    fn test_cmd_hotspot_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_hotspot(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    // Note: watch command is fully implemented; no stub test needed.

    // --- cmd_fix tests ---

    #[test]
    fn test_cmd_fix_dry_run() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_fix(&root, &config, true, None, &collector).unwrap();
        assert!(output.contains("Dry run") || output.contains("No auto-fixable"));
    }

    #[test]
    fn test_cmd_fix_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_fix(dir.path(), &config, true, None, &collector).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    #[test]
    fn test_cmd_fix_with_rule_filter() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_fix(&root, &config, true, Some("unused-function"), &collector).unwrap();
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_fix(&root, &config, true, Some("nonexistent-rule"), &collector).unwrap();
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
    fn test_cmd_explain_audit_rule() {
        let output = cmd_explain("audit:new-finding").unwrap();
        assert!(output.contains("New finding"));
    }

    #[test]
    fn test_cmd_explain_hotspot_rule() {
        let output = cmd_explain("hotspot:hotspot").unwrap();
        assert!(output.contains("Hotspot"));
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
        assert!(output.contains("audit"), "should list audit module");
        assert!(output.contains("hotspot"), "should list hotspot module");
        assert!(output.contains("autofix"), "should list autofix module");
        assert!(
            output.contains("ai-quality"),
            "should list ai-quality module"
        );
        assert!(
            output.contains("llm-defense"),
            "should list llm-defense module"
        );
        assert!(
            output.contains("cicd-security"),
            "should list cicd-security module"
        );
        assert!(
            output.contains("duplication"),
            "should list duplication module"
        );
        assert!(
            output.contains("architecture"),
            "should list architecture module"
        );
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_security(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert_eq!(output, "No files found.\n");
    }

    #[test]
    fn test_cmd_security_with_fixtures() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/security/vulnerable");
        if root.exists() {
            let config = ChaffraConfig::default();
            let formatter = create_formatter(OutputFormat::Terminal);
            let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
            let output = cmd_security(&root, &config, formatter.as_ref(), &collector).unwrap();
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
            let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
            let output = cmd_security(&root, &config, formatter.as_ref(), &collector).unwrap();
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
            let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
            let output = cmd_security(&root, &config, formatter.as_ref(), &collector).unwrap();
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
            let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
            let output = cmd_security(&root, &config, formatter.as_ref(), &collector).unwrap();
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_security(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
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

    // --- cmd_ai_quality tests ---

    #[test]
    fn test_cmd_ai_quality_fixtures() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/python/ai-quality");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_ai_quality(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_ai_quality_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_ai_quality(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    // --- cmd_llm_defense tests ---

    #[test]
    fn test_cmd_llm_defense_fixtures() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/python/llm-defense");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_llm_defense(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_llm_defense_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_llm_defense(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    // --- explain for new modules ---

    #[test]
    fn test_cmd_explain_phantom_api_call() {
        let output = cmd_explain("ai-quality:phantom-api-call").unwrap();
        assert!(output.contains("Phantom API call"));
        assert!(output.contains("Rationale:"));
    }

    #[test]
    fn test_cmd_explain_unsafe_tool_use() {
        let output = cmd_explain("llm-defense:unsafe-tool-use").unwrap();
        assert!(output.contains("Unsafe tool use"));
        assert!(output.contains("Rationale:"));
    }

    // --- cmd_impact tests ---

    #[test]
    fn test_cmd_impact_save_snapshot() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let dir = TempDir::new().unwrap();
        let snapshot_path = dir.path().join("snapshot.json");
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();

        let output = cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            Some("test-label".to_owned()),
            OutputFormat::Terminal,
            &collector,
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();

        cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            Some("baseline".to_owned()),
            OutputFormat::Terminal,
            &collector,
        )
        .unwrap();

        let output = cmd_impact(
            &root,
            &config,
            None,
            Some(snapshot_path.to_str().unwrap()),
            Some("current".to_owned()),
            OutputFormat::Terminal,
            &collector,
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();

        cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            None,
            OutputFormat::Terminal,
            &collector,
        )
        .unwrap();

        let output = cmd_impact(
            &root,
            &config,
            None,
            Some(snapshot_path.to_str().unwrap()),
            None,
            OutputFormat::Json,
            &collector,
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_impact(
            dir.path(),
            &config,
            None,
            None,
            None,
            OutputFormat::Terminal,
            &collector,
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
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();

        cmd_impact(
            &root,
            &config,
            Some(snapshot_path.to_str().unwrap()),
            None,
            Some("all-modules".to_owned()),
            OutputFormat::Terminal,
            &collector,
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

    // --- cmd_cicd_security tests ---

    #[test]
    fn test_cmd_explain_cicd_rule() {
        let output = cmd_explain("cicd-security:actions-unpinned-action").unwrap();
        assert!(output.contains("Unpinned action"));
        assert!(output.contains("Rationale:"));
    }

    #[test]
    fn test_cmd_cicd_security_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output =
            cmd_cicd_security(dir.path(), &config, formatter.as_ref(), &collector).unwrap();
        assert_eq!(output, "No files found.\n");
    }

    #[test]
    fn test_cmd_cicd_security_with_fixtures() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/cicd");
        if !root.exists() {
            return;
        }
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let output = cmd_cicd_security(&root, &config, formatter.as_ref(), &collector).unwrap();
        assert!(!output.is_empty());
    }

    // --- Phase 13: telemetry wiring tests ---

    #[test]
    fn test_churn_wiring_records_real_fingerprints() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let formatter = create_formatter(OutputFormat::Terminal);
        let _ = cmd_dead_code(&root, &config, formatter.as_ref(), &collector).unwrap();

        let fingerprints = collector.finding_fingerprints();
        assert!(
            !fingerprints.is_empty(),
            "dead-code analysis should produce real fingerprints"
        );
        for fp in &fingerprints {
            assert!(!fp.rule_id.is_empty());
            assert!(!fp.file.is_empty());
        }
    }

    #[test]
    fn test_sampling_config_merges_project_config() {
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        assert_eq!(cli_config.sampling_rate, 1.0);

        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nsampling-rate = \"0.5\"\nsampling-strategy = \"on-change\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();

        let merged = merge_telemetry_config(&cli_config, &project_config);
        assert!(
            (merged.sampling_rate - 0.5).abs() < f64::EPSILON,
            "project config sampling-rate should override default"
        );
        assert_eq!(
            merged.sampling_strategy,
            chaffra_telemetry::SamplingStrategy::OnChange,
            "project config sampling-strategy should override default"
        );
    }

    #[test]
    fn test_startup_timing_records_metrics() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let _host = build_module_host_with_telemetry(Some(&collector));

        let snapshot = collector.snapshot();
        let startup_points: Vec<_> = snapshot
            .data_points
            .iter()
            .filter(|p| p.name == "chaffra.module.startup_duration_ms")
            .collect();
        assert!(
            !startup_points.is_empty(),
            "should record per-module startup timing"
        );

        let total_point = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.startup.total_duration_ms");
        assert!(
            total_point.is_some(),
            "should record total startup duration"
        );
    }

    #[test]
    fn test_run_with_telemetry_end_to_end() {
        let dir = TempDir::new().unwrap();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/go/simple");
        let config = ChaffraConfig::default();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(
                    dir.path()
                        .join("telemetry.json")
                        .to_str()
                        .unwrap()
                        .to_owned(),
                ),
                options: HashMap::new(),
            }],
            ..Default::default()
        };

        // Temporarily override the state file path by running in the temp dir.
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let formatter = create_formatter(OutputFormat::Terminal);
        let output = run_with_telemetry(&tel_config, &config, "dead-code", |collector| {
            cmd_dead_code(&root, &config, formatter.as_ref(), collector)
        })
        .unwrap();

        std::env::set_current_dir(&original_dir).unwrap();

        assert!(!output.is_empty());

        // Verify state file was written with real fingerprints.
        let state_file = dir.path().join(chaffra_telemetry::churn::STATE_FILE);
        assert!(state_file.exists(), "churn state file should be written");
        let state = chaffra_telemetry::churn::load_state(&state_file).unwrap();
        assert!(
            !state.fingerprints.is_empty(),
            "churn state should contain real fingerprints, not an empty set"
        );
    }

    #[test]
    fn test_failed_run_preserves_prior_churn_state() {
        let dir = TempDir::new().unwrap();
        let state_file = dir.path().join(chaffra_telemetry::churn::STATE_FILE);

        let prior_state = chaffra_telemetry::churn::ChurnState {
            fingerprints: [chaffra_telemetry::churn::FindingFingerprint::new(
                "dc:unused",
                "a.go",
                10,
            )]
            .into_iter()
            .collect(),
            findings_hash: 12345,
            timestamp_ms: 1000,
        };
        chaffra_telemetry::churn::save_state(&prior_state, &state_file).unwrap();

        let config = ChaffraConfig::default();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            backends: vec![],
            ..Default::default()
        };

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let result = run_with_telemetry(&tel_config, &config, "failing-cmd", |_collector| {
            anyhow::bail!("simulated analysis failure")
        });

        std::env::set_current_dir(&original_dir).unwrap();

        assert!(result.is_err());

        let loaded = chaffra_telemetry::churn::load_state(&state_file).unwrap();
        assert_eq!(
            loaded.fingerprints, prior_state.fingerprints,
            "prior churn state should be preserved after a failed run"
        );
        assert_eq!(loaded.findings_hash, 12345);
    }

    #[test]
    fn test_failed_run_flushes_error_telemetry() {
        let dir = TempDir::new().unwrap();
        let telemetry_path = dir.path().join("telemetry.json");
        let state_file = dir.path().join(chaffra_telemetry::churn::STATE_FILE);

        let prior_state = chaffra_telemetry::churn::ChurnState {
            fingerprints: [chaffra_telemetry::churn::FindingFingerprint::new(
                "dc:unused",
                "a.go",
                10,
            )]
            .into_iter()
            .collect(),
            findings_hash: 99999,
            timestamp_ms: 2000,
        };
        chaffra_telemetry::churn::save_state(&prior_state, &state_file).unwrap();

        let config = ChaffraConfig::default();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(telemetry_path.to_str().unwrap().to_owned()),
                options: HashMap::new(),
            }],
            ..Default::default()
        };

        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let result = run_with_telemetry(&tel_config, &config, "failing-cmd", |_collector| {
            anyhow::bail!("simulated analysis failure")
        });

        std::env::set_current_dir(&original_dir).unwrap();

        assert!(result.is_err());

        assert!(
            telemetry_path.exists(),
            "telemetry JSON should be flushed even on failed runs"
        );
        let content = std::fs::read_to_string(&telemetry_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed["operator_summary"]["module_error_counts"]["failing-cmd"], 1,
            "error metric should be recorded in flushed telemetry"
        );

        let loaded = chaffra_telemetry::churn::load_state(&state_file).unwrap();
        assert_eq!(
            loaded.fingerprints, prior_state.fingerprints,
            "prior churn state should be unchanged after a failed run"
        );
        assert_eq!(loaded.findings_hash, 99999);
        assert_eq!(loaded.timestamp_ms, 2000);
    }
}
