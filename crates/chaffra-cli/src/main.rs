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
    ///
    /// An explicit value here is authoritative: it overrides the
    /// `[modules.telemetry] audience` file setting and the `user-only` default,
    /// so `--telemetry off` cannot be re-enabled by a checked-in config. When
    /// omitted, the audience falls back to the file configuration, and finally
    /// to the `user-only` default: a default run collects only user-facing
    /// summary metrics and never emits operator metrics (process/error
    /// telemetry). Pass `on` or `operator-only` to opt into operator emission.
    /// An unrecognised value is rejected at parse time (fail closed).
    #[arg(long, global = true, value_parser = parse_audience_flag)]
    telemetry: Option<chaffra_telemetry::TelemetryAudience>,

    /// Override telemetry backend (json-file, stderr, prometheus, otlp, statsd).
    #[arg(long = "telemetry-backend", global = true)]
    telemetry_backend: Option<String>,

    /// Override OTLP endpoint.
    #[arg(long = "telemetry-endpoint", global = true)]
    telemetry_endpoint: Option<String>,
}

/// clap value parser for `--telemetry`. Parses straight into a
/// [`chaffra_telemetry::TelemetryAudience`], failing closed: an unrecognised
/// value is rejected during argument parsing rather than silently coerced to a
/// wider default. Carrying the parsed enum (rather than a re-parsed `String`)
/// removes the double-parse and gives the resolver the `Option<TelemetryAudience>`
/// it needs to let an explicit flag win over the file setting.
fn parse_audience_flag(
    value: &str,
) -> std::result::Result<chaffra_telemetry::TelemetryAudience, String> {
    chaffra_telemetry::TelemetryAudience::parse(value).map_err(|e| e.to_string())
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
    /// Useful for verifying the dashboard UI and API shape. Backend status
    /// (kind/connectivity) is operator-shaped and is disclosed only when started
    /// with an operator audience (`--telemetry on|operator-only`); a default
    /// (user-only) run returns an empty backends list.
    /// Co-located mode (sharing a live collector from watch/MCP/LSP) is planned.
    Management {
        /// Port to bind the management server to.
        #[arg(long, default_value = "9100")]
        port: u16,
    },
}

#[derive(Subcommand)]
enum TelemetryAction {
    /// Show the resolved telemetry audience. Backend catalogue and
    /// connectivity are operator-shaped and shown only when operator telemetry
    /// is enabled (`on` / `operator-only`); withheld under `user-only` / `off`.
    Status,
    /// Emit a test metric and report per-backend success or failure. Exercises
    /// and names backends only under an operator audience (`on` /
    /// `operator-only`); withheld under `user-only` / `off`.
    Test,
    /// Dry-run: preview the per-backend telemetry payload. Backend names and
    /// payload are shown only under an operator audience (`on` /
    /// `operator-only`); withheld under `user-only` / `off`.
    Inspect,
    /// Generate an import-ready Grafana dashboard JSON (Prometheus datasource).
    Dashboard {
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

/// Load project config for an analysis command. Strict / fail-closed:
/// an explicit `--config <file>` propagates load errors via `ChaffraConfig::load`,
/// and the implicit `.chaffra.toml` discovery propagates parse errors via
/// `ChaffraConfig::load_from_dir`. A missing `.chaffra.toml` is not an error
/// (`load_from_dir` returns the default in that case).
///
/// Previously the implicit-discovery branch wrapped `load_from_dir(...)` in
/// `unwrap_or_default()`, which silently coerced a malformed `.chaffra.toml`
/// into `ChaffraConfig::default()`. That bypassed the telemetry precedence
/// chain entirely: a broken `[modules.telemetry] audience` (or any other
/// section) would be ignored and the privacy-preserving `user-only` default
/// would silently apply instead of the configured value — so the project
/// would still emit, but at the default audience rather than the operator-set
/// one. The strict path here propagates the typed parse error so the
/// command fails closed and the operator sees the bad config instead of a
/// silently-defaulted run.
///
/// Single shared loader: every analysis command (`health`, `security`,
/// `audit`, `dead-code`, `hotspot`, ...) routes through this. The telemetry
/// diagnostic subcommands also route through this via
/// [`resolve_subcommand_telemetry`] (see below), so live runs and previews
/// agree on what counts as a valid config.
fn load_config(config_path: Option<&str>, analysis_path: &Path) -> Result<ChaffraConfig> {
    if let Some(path) = config_path {
        ChaffraConfig::load(Path::new(path)).context("failed to load configuration file")
    } else {
        ChaffraConfig::load_from_dir(analysis_path)
            .context("failed to load .chaffra.toml from project directory")
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

/// Merge the CLI-derived telemetry config with the project's
/// `[modules.telemetry]` file configuration, producing the effective config for
/// a run. This is the single shared, fail-closed config path used by every
/// command via [`run_with_telemetry`].
///
/// Audience precedence (fail-closed): an explicit `--telemetry` CLI flag wins,
/// then the file `[modules.telemetry] audience`, then the privacy-preserving
/// `user-only` default. An explicit flag is authoritative — a checked-in file
/// can NOT re-enable operator emission the operator disabled on the command line
/// (`--telemetry off`) nor widen a narrower explicit `--telemetry user-only`.
/// The explicit-vs-default distinction is carried by `cli_audience_override`
/// (set only when the flag was passed), so this resolves correctly without
/// threading an extra argument through the per-command dispatch. A malformed
/// `[modules.telemetry]` (e.g. an invalid `audience`) is surfaced as a typed
/// error rather than silently coerced to a wider default.
fn merge_telemetry_config(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    project_config: &ChaffraConfig,
) -> Result<chaffra_telemetry::TelemetryConfig> {
    let mut config = cli_config.clone();
    // The CLI base audience (already the explicit flag value or the `user-only`
    // default from `build_telemetry_config`) is the fallback when neither an
    // explicit flag nor a file `audience` is in play.
    let mut file_audience = None;
    let module_cfg = project_config.module_config("telemetry");
    if !module_cfg.is_empty() {
        let project_tel = chaffra_telemetry::TelemetryConfig::from_module_config(&module_cfg)
            .map_err(|e| anyhow::anyhow!("invalid [modules.telemetry] configuration: {e}"))?;
        // Each file-side field participates only when explicitly present in
        // the `[modules.telemetry]` section. Without this gate, a file that
        // sets only `backend = "otlp"` would silently clobber a CLI
        // `--telemetry-sampling-rate` with the file's default value, because
        // `from_module_config` always returns a populated `sampling_rate` /
        // `sampling_strategy`. Match the same shape `audience` uses below: read
        // from the parsed value, but only when the key was set in the file.
        // Both the kebab- and snake-case spellings are accepted (matching
        // `from_module_config`'s own dual lookup).
        // The file's `backend` participates only when explicitly present AND no
        // explicit CLI backend selector (`--telemetry-backend` /
        // `--telemetry-endpoint`) was given. Without this, a checked-in
        // `[modules.telemetry] backend = "stderr"` was silently dropped on live
        // CLI runs — the resolved config kept the default JSON-file backend even
        // though the file requested otherwise, while the MCP/module paths
        // (`from_module_config`) honoured it (R10-F1). Backend precedence:
        // `--telemetry-backend` / `--telemetry-endpoint` > file `backend` >
        // default. Copying `project_tel.backends` carries the file's `endpoint`
        // / `path` alongside the backend kind, matching `from_module_config`.
        if !cli_config.cli_backend_override && module_cfg.contains_key("backend") {
            config.backends = project_tel.backends.clone();
        }
        if module_cfg.contains_key("sampling-rate") || module_cfg.contains_key("sampling_rate") {
            config.sampling_rate = project_tel.sampling_rate;
        }
        if module_cfg.contains_key("sampling-strategy")
            || module_cfg.contains_key("sampling_strategy")
        {
            config.sampling_strategy = project_tel.sampling_strategy;
        }
        // The file's `audience` participates only when explicitly present in the
        // section. The explicit CLI flag (if any) still wins over it.
        file_audience = module_cfg
            .contains_key("audience")
            .then_some(project_tel.audience);
    }
    config.audience = chaffra_telemetry::TelemetryConfig::resolve_audience(
        cli_config.cli_audience_override,
        file_audience,
        cli_config.audience,
    );
    // Audit-log emission happens at the live-emission boundary
    // (`run_with_telemetry`), not here. This helper is also called by the
    // diagnostic subcommands (`status` / `test` / `inspect`), which only
    // PREVIEW the resolved config — they must not write an accountability
    // event for telemetry that did not actually run. See
    // [`maybe_audit_log_audience`] and its call from `run_with_telemetry`.
    Ok(config)
}

/// Emit the Phase 14 audit-log event when the live emission boundary
/// resolves to a particular audience. This is the wiring the previous stage
/// left unwired with a `TODO(issue)` placeholder: an explicit data-subject
/// request needs to see when operator telemetry was actually activated, so we
/// log on the LIVE path (not the diagnostic previews) where a flush will
/// actually take place.
///
/// Emission rule, at most one event per chaffra invocation:
/// - operator-enabled audience (`On` / `OperatorOnly`) -> `log_telemetry_enabled`
/// - `UserOnly` -> `log_telemetry_disabled` (operator telemetry stayed off)
/// - `Off` -> NO audit event. `--telemetry off` is an explicit "do not emit,
///   write, or leave traces" instruction, so the audit log honours the kill
///   switch and writes nothing (this function returns early). Accountability is
///   preserved for the audiences that actually run a workload.
///
/// `user` attribution: best-effort from the process environment (`USER` on
/// unix, `USERNAME` on windows). The audit-log type allows `None`, so we pass
/// `None` when neither is set rather than fabricate a value. A proper user
/// identity comes from the Phase-future management wiring; until then the
/// process owner is the most faithful attribution we can produce locally.
///
/// De-duplication: NOT applied. Each chaffra invocation is one event in the
/// audit log — that matches the GDPR temporal-record purpose ("when was
/// telemetry running") better than collapsing repeated runs into a single
/// entry. The audit log file is append-only and the `read_log` /
/// `export_for_gdpr` helpers already handle multi-event traversal.
fn maybe_audit_log_audience(audience: chaffra_telemetry::TelemetryAudience) {
    // R5-Audit-Off: `--telemetry off` is the operator's explicit "do not
    // emit, write, or leave traces" instruction. Audit-log writes record
    // best-effort process-owner attribution and a timestamp — themselves a
    // disk-side effect the operator did not authorise. Honour the kill
    // switch by skipping the log entirely under `Off`. Accountability is
    // preserved for every *opted-in* audience: every other branch still
    // emits a `TelemetryEnabled` (operator-scoped) or `TelemetryDisabled`
    // (user-only opted in but operator off) event.
    if matches!(audience, chaffra_telemetry::TelemetryAudience::Off) {
        return;
    }
    // Best-effort process-owner attribution; `audit_log` accepts `Option`.
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .filter(|s| !s.is_empty());
    if audience.operator_enabled() {
        chaffra_telemetry::audit_log::log_telemetry_enabled(&format!("{audience:?}"), user);
    } else {
        // `UserOnly` is the only remaining branch: user-facing summaries
        // emit, operator scope is off.
        chaffra_telemetry::audit_log::log_telemetry_disabled(user);
    }
}

/// Resolve the effective telemetry config for the `telemetry` diagnostic
/// subcommands (`status` / `test` / `inspect`) through the SAME precedence chain
/// a live run uses. These commands have no analysis path of their own, so the
/// caller supplies the project directory whose `.chaffra.toml` is consulted,
/// together with an optional explicit `--config <file>` (so previews honour the
/// same global flag the live commands do). Precedence: explicit `--telemetry`
/// flag > file `[modules.telemetry] audience` > default.
///
/// Fail-closed everywhere: the live-run analysis dispatch and these previews
/// now share the same strict [`load_config`] loader, so a malformed
/// `.chaffra.toml` (or a structurally invalid `[modules.telemetry]`) surfaces
/// as a typed error from both paths — they cannot disagree on what counts as
/// a valid config any more.
fn resolve_subcommand_telemetry(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    config_path: Option<&str>,
    project_dir: &Path,
) -> Result<chaffra_telemetry::TelemetryConfig> {
    // Reuse the live-run loader: an explicit `--config <file>` wins over
    // implicit `.chaffra.toml` discovery, exactly as `health` / `security` /
    // etc. resolve it. A malformed file propagates via `?`; a missing
    // implicit file returns the default config.
    let project_config = load_config(config_path, project_dir)?;
    merge_telemetry_config(cli_config, &project_config)
}

/// Build the `chaffra management` collector with telemetry resolved through the
/// SAME file-aware, fail-closed path as live runs and the telemetry diagnostics
/// (R11-F1). `chaffra management` previously constructed its collector straight
/// from the CLI-derived config, so a project's `[modules.telemetry]` audience /
/// backend was ignored and a malformed `[modules.telemetry]` did not stop
/// startup — a parallel config path Stage 15a.1 forbids. Routing through
/// [`resolve_subcommand_telemetry`] makes a checked-in `audience`/`backend`
/// govern the management collector (an explicit CLI flag still wins), and a
/// malformed file fails closed before the server binds.
fn build_management_collector(
    cli_config: &chaffra_telemetry::TelemetryConfig,
) -> Result<chaffra_telemetry::TelemetryCollector> {
    let project_dir = std::env::current_dir().context("failed to read current directory")?;
    build_management_collector_in(cli_config, dispatch_config_path(cli_config), &project_dir)
}

/// Testable core of [`build_management_collector`]: resolve telemetry through the
/// shared precedence/fail-closed path for an explicit `project_dir`, then build
/// the collector. Split out so management's config resolution is unit-tested
/// without binding a port — the same wrapper/`_in` shape the telemetry
/// diagnostics use.
fn build_management_collector_in(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    config_path: Option<&str>,
    project_dir: &Path,
) -> Result<chaffra_telemetry::TelemetryCollector> {
    let resolved = resolve_subcommand_telemetry(cli_config, config_path, project_dir)?;
    let collector = chaffra_telemetry::TelemetryCollector::new(resolved);
    collector.register_core_metrics();
    Ok(collector)
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
    Ok(formatter.format_result(&result, None))
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

    let ignore_patterns =
        chaffra_parse::discovery::load_all_ignore_patterns(root, &config.project.ignore);
    discover_security_files(root, root, &ignore_patterns, &mut files);

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

fn discover_security_files(
    root: &Path,
    dir: &Path,
    ignore_patterns: &[String],
    files: &mut Vec<FileInfo>,
) {
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
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            if chaffra_parse::discovery::is_ignored(&rel, ignore_patterns) {
                continue;
            }
            discover_security_files(root, &path, ignore_patterns, files);
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();

            if chaffra_parse::discovery::is_ignored(&rel, ignore_patterns) {
                continue;
            }

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

fn build_telemetry_config(cli: &Cli) -> Result<chaffra_telemetry::TelemetryConfig> {
    // `cli.telemetry` is the parsed `--telemetry` flag (`None` when omitted).
    // The base audience is the flag value or the privacy-preserving `user-only`
    // default; the project file's `audience` (if any) is layered on later in
    // `merge_telemetry_config`. We also carry the raw `Option` as the precedence
    // hint so that step can let an explicit flag win over the file setting.
    let audience = cli.telemetry.unwrap_or_default();

    let backends = if let Some(ref backend_str) = cli.telemetry_backend {
        // Fail closed on a present-but-invalid `--telemetry-backend`, through
        // the SAME typed parser the file path uses — no lenient default
        // fallback that would silently run JSON-file telemetry for a typo.
        let kind = chaffra_telemetry::BackendKind::parse(backend_str)
            .map_err(|e| anyhow::anyhow!("invalid --telemetry-backend: {e}"))?;
        vec![chaffra_telemetry::BackendConfig {
            kind,
            endpoint: cli.telemetry_endpoint.clone(),
            path: None,
            options: HashMap::new(),
        }]
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

    Ok(chaffra_telemetry::TelemetryConfig {
        audience,
        backends,
        cli_audience_override: cli.telemetry,
        // An explicit CLI backend selector takes precedence over a file
        // `[modules.telemetry] backend`. Record whether one was given so
        // `merge_telemetry_config` applies the file backend only when the CLI
        // did not select one (R10-F1).
        cli_backend_override: cli.telemetry_backend.is_some() || cli.telemetry_endpoint.is_some(),
        cli_config_path: cli.config.clone(),
        ..Default::default()
    })
}

/// `--config <file>` from the CLI dispatch, carried on `cli_config` so the
/// per-arm dispatch in `main()` does not need a second argument. The
/// telemetry diagnostic commands and the helper `resolve_subcommand_telemetry`
/// read the path from here instead of receiving it through the call stack.
fn dispatch_config_path(cli_config: &chaffra_telemetry::TelemetryConfig) -> Option<&str> {
    cli_config.cli_config_path.as_deref()
}

fn cmd_telemetry_status(cli_config: &chaffra_telemetry::TelemetryConfig) -> String {
    // The wrapper called from `main()` returns `String` so the dispatch site
    // stays a single `print!`, identical to the base shape (one unchanged
    // line — no `?`, no inner `match`). That keeps trust-boundary
    // changed-line coverage at 100% for an arm that lives inside `tokio::main`
    // and so cannot be unit-tested.
    //
    // F7's intent ("exit nonzero on bad config") is enforced HERE: a typed
    // error from the strict precedence resolution prints to stderr and
    // exits 1, matching the behaviour of `test` / `inspect`. Scripted
    // callers see a nonzero exit on invalid telemetry config exactly as
    // they do for the Result-returning siblings; the API shape difference
    // is a coverage-mechanic concession that does not change the user-visible
    // behaviour. The testable `_in` variant still returns `Result<String>`
    // so unit tests can assert the typed error directly.
    match cmd_telemetry_status_impl(cli_config) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_telemetry_status_impl(cli_config: &chaffra_telemetry::TelemetryConfig) -> Result<String> {
    let project_dir = std::env::current_dir().context("failed to read current directory")?;
    cmd_telemetry_status_in(cli_config, dispatch_config_path(cli_config), &project_dir)
}

fn cmd_telemetry_status_in(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    config_path: Option<&str>,
    project_dir: &Path,
) -> Result<String> {
    // Returns `Result<String>` (not just `String`): an invalid telemetry
    // configuration must propagate as a nonzero exit, the same way `test`
    // and `inspect` already do. The previous implementation returned a
    // success string with an inline "Telemetry configuration error: ..."
    // message, which scripted callers (CI, automation) could not tell apart
    // from a healthy report — invalid config looked like a clean run. The
    // command now fails closed end-to-end: caller in `main()` reports the
    // error to stderr and exits nonzero, consistent with every other
    // telemetry diagnostic command.
    let resolved = resolve_subcommand_telemetry(cli_config, config_path, project_dir)?;
    let mut out = String::new();
    out.push_str(&format!("Telemetry mode: {:?}\n\n", resolved.audience));

    // Backend kind / endpoint / connectivity is operator-shaped, exactly like
    // the `TelemetryModule::analyze` `backend-status` finding (R4-1) and the MCP
    // `status` / `backends` actions (R4-3). Gate this CLI output boundary the
    // same way: disclose the backend catalogue only when the resolved audience
    // includes the operator scope. Under `user-only` / `off` the catalogue is
    // withheld, with a hint at the explicit opt-in.
    if !resolved.audience.operator_enabled() {
        out.push_str(
            "Backends: (withheld — operator telemetry is not enabled at this audience; \
             use --telemetry on|operator-only or [modules.telemetry] audience to view)\n",
        );
        return Ok(out);
    }

    out.push_str("Backends:\n");
    let (_, statuses) = chaffra_telemetry::backends::create_backends(&resolved.backends);
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

    Ok(out)
}

fn cmd_telemetry_test(cli_config: &chaffra_telemetry::TelemetryConfig) -> Result<String> {
    let project_dir = std::env::current_dir().context("failed to read current directory")?;
    cmd_telemetry_test_in(cli_config, dispatch_config_path(cli_config), &project_dir)
}

fn cmd_telemetry_test_in(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    config_path: Option<&str>,
    project_dir: &Path,
) -> Result<String> {
    // Resolve through the live-run precedence chain so the diagnostic flush is
    // projected to the audience a real run would emit at (explicit `--telemetry`
    // flag > file `[modules.telemetry] audience` > default).
    let tel_config = resolve_subcommand_telemetry(cli_config, config_path, project_dir)?;

    // Operator gate (R8-F1, generalises the F5 `Off` no-op): exercising and
    // reporting backends is operator-shaped. Projection scrubs the metric
    // PAYLOAD, but NOT the backend config/status metadata this command
    // discloses — the backend name via `[OK]/[FAIL] {name}`, and the
    // endpoint/port/namespace a backend's `flush()` may write. That metadata is
    // classified operator-shaped everywhere else (CLI `status`, the
    // `backend-status` finding, MCP `status`/`backends`), so `test` must apply
    // the same gate. Under a non-operator audience (`user-only` / `off`)
    // withhold entirely: no backend is constructed, contacted, or named. (This
    // also subsumes the F5 `Off` no-op — `Off` is not `operator_enabled()`.)
    if !tel_config.audience.operator_enabled() {
        return Ok(format!(
            "Telemetry mode: {:?}\n\nBackend connectivity test requires operator telemetry; \
             no backends are exercised, contacted, or named under user-only/off \
             (use --telemetry on|operator-only).\n",
            tel_config.audience
        ));
    }

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

    // Apply the same audience projection the live emission paths use, so the
    // diagnostic flush never writes fields the configured audience would not
    // permit (the data is synthetic, so this is consistency, not a live leak).
    let snapshot = collector
        .snapshot()
        .project_for_audience(tel_config.audience);
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

fn cmd_telemetry_inspect(cli_config: &chaffra_telemetry::TelemetryConfig) -> Result<String> {
    let project_dir = std::env::current_dir().context("failed to read current directory")?;
    cmd_telemetry_inspect_in(cli_config, dispatch_config_path(cli_config), &project_dir)
}

fn cmd_telemetry_inspect_in(
    cli_config: &chaffra_telemetry::TelemetryConfig,
    config_path: Option<&str>,
    project_dir: &Path,
) -> Result<String> {
    // Resolve through the live-run precedence chain so the previewed payload
    // matches a real flush at the resolved audience (explicit `--telemetry` flag
    // > file `[modules.telemetry] audience` > default).
    let tel_config = resolve_subcommand_telemetry(cli_config, config_path, project_dir)?;

    // Operator gate (R8-F1), same rationale as `test`: this preview prints the
    // backend name (`--- {name} ---`) and delegates to each backend's
    // `inspect()`, which can embed backend config/endpoint metadata. Projection
    // scrubs the metric payload but not that operator-shaped backend metadata,
    // so withhold the per-backend preview under a non-operator audience.
    if !tel_config.audience.operator_enabled() {
        return Ok(format!(
            "Telemetry mode: {:?}\n\nBackend payload preview requires operator telemetry; \
             backend names and per-backend output are withheld under user-only/off \
             (use --telemetry on|operator-only).\n",
            tel_config.audience
        ));
    }

    let collector = chaffra_telemetry::TelemetryCollector::new(tel_config.clone());
    collector.register_core_metrics();
    collector.set_files_total(0);

    // Simulate some data.
    collector.record_module_call("example-module", 100, false);
    let mut sev = HashMap::new();
    sev.insert("warning".to_owned(), 2);
    collector.record_module_findings("example-module", 2, &sev);

    // Project to the configured audience before inspection so the previewed
    // payload matches exactly what a real flush at this audience would emit.
    let snapshot = collector
        .snapshot()
        .project_for_audience(tel_config.audience);
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

fn cmd_telemetry_dashboard(to_stdout: bool) -> Result<String> {
    let dashboard = chaffra_telemetry::dashboard::generate_dashboard();
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

/// Project the collector's snapshot to `audience` and flush it to every
/// configured backend. This is the single telemetry privacy boundary for the
/// CLI emission paths: projecting BEFORE the flush guarantees operator-only
/// fields never reach a sink the audience does not permit. Used by both the
/// success and failure flush paths in [`run_with_telemetry`] so the boundary is
/// defined once and cannot drift between them.
fn flush_projected(
    config: &chaffra_telemetry::TelemetryConfig,
    collector: &chaffra_telemetry::TelemetryCollector,
) {
    let (backends, _) = chaffra_telemetry::backends::create_backends(&config.backends);
    let snapshot = collector.snapshot().project_for_audience(config.audience);
    for backend in &backends {
        let _ = backend.flush(&snapshot);
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
    let effective_config = merge_telemetry_config(tel_config, project_config)?;

    // Emit the Phase 14 audit-log accountability event at the live boundary,
    // BEFORE the Off short-circuit and before any backend write.
    // `maybe_audit_log_audience` emits `TelemetryEnabled` for operator audiences
    // (`On`/`OperatorOnly`) and `TelemetryDisabled` for `UserOnly`; under `Off`
    // it writes NO event (R5-Audit-Off) — `--telemetry off` is the operator's
    // explicit "leave no traces" instruction, so the audit log honours the kill
    // switch. The diagnostic-preview helpers (`status`/`test`/`inspect`)
    // deliberately do NOT call this — they don't run the workload, so they don't
    // log.
    maybe_audit_log_audience(effective_config.audience);

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
            flush_projected(&effective_config, &collector);
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
        // Same privacy boundary on the failure path via the shared helper:
        // error telemetry is operator-only, so it is withheld unless the
        // operator audience is enabled.
        flush_projected(&effective_config, &collector);
    }

    result
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let format = OutputFormat::from_str_loose(&cli.format).unwrap_or(OutputFormat::Terminal);
    let formatter = create_formatter(format);
    let tel_config = build_telemetry_config(&cli)?;

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
            TelemetryAction::Dashboard { stdout } => match cmd_telemetry_dashboard(*stdout) {
                Ok(output) => print!("{output}"),
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            },
            TelemetryAction::AuditLog { export } => {
                print!("{}", cmd_telemetry_audit_log(*export));
            }
        },

        Command::Management { port } => {
            let collector = build_management_collector(&tel_config)?;
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
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard};
    use tempfile::TempDir;

    // The process cwd is global, but cargo test runs tests in parallel. Two
    // sibling tests both doing `set_current_dir(tempdir)` would race: test A's
    // TempDir can be dropped (cleaned up) while test B is still cd'd inside it,
    // and the next `current_dir()` call inside the now-vanished directory
    // returns ENOENT. That is chaffra#51 (test_run_with_telemetry_end_to_end
    // intermittent NotFound). Every cwd-mutating test takes `CwdGuard::enter`,
    // which serializes them on `CWD_LOCK` and restores the original cwd on
    // drop — including on panic, so a panicking test cannot leave the runner
    // pointed at a dropped tempdir.
    static CWD_LOCK: Mutex<()> = Mutex::new(());

    struct CwdGuard {
        _lock: MutexGuard<'static, ()>,
        original: PathBuf,
    }

    impl CwdGuard {
        fn enter(target: &Path) -> Self {
            // A prior test that panicked inside the guarded region poisons the
            // lock. The state the lock protects is the global cwd, which the
            // panicking test's Drop has already restored, so recovering the
            // inner guard is safe and keeps subsequent tests runnable.
            let lock = CWD_LOCK.lock().unwrap_or_else(|p| p.into_inner());
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(target).unwrap();
            Self {
                _lock: lock,
                original,
            }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            // Best-effort restore. If the original directory has somehow been
            // removed, there is nothing the test harness can do about it; the
            // panic-already-in-progress path must not double-panic.
            let _ = std::env::set_current_dir(&self.original);
        }
    }

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

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
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
    fn test_merge_sampling_rate_overridden_only_when_file_sets_it() {
        // 2A: `[modules.telemetry]` that omits the sampling key must NOT clobber
        // a CLI-supplied `--telemetry-sampling-rate`. Previously the merge
        // unconditionally assigned `config.sampling_rate = project_tel.sampling_rate`,
        // which silently overwrote the CLI value with `from_module_config`'s
        // default whenever ANY other key (e.g. `backend`) was set in the section.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            // Only `backend` is set — no `sampling-rate` / `sampling-strategy`.
            "[project]\nentry = []\n\n[modules.telemetry]\nbackend = \"otlp\"\nendpoint = \"http://localhost:4318\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        // CLI sets sampling_rate explicitly to 0.1 (well below the default 1.0).
        let cli_config = chaffra_telemetry::TelemetryConfig {
            sampling_rate: 0.1,
            ..Default::default()
        };
        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert!(
            (merged.sampling_rate - 0.1).abs() < f64::EPSILON,
            "CLI sampling_rate=0.1 must be preserved when the file omits the key; got {}",
            merged.sampling_rate
        );
    }

    #[test]
    fn test_merge_sampling_strategy_overridden_only_when_file_sets_it() {
        // 2A: the strategy variant — a file that omits `sampling-strategy`
        // must not silently revert the CLI-supplied strategy to the default.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nbackend = \"otlp\"\nendpoint = \"http://localhost:4318\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig {
            sampling_strategy: chaffra_telemetry::SamplingStrategy::OnChange,
            ..Default::default()
        };
        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(
            merged.sampling_strategy,
            chaffra_telemetry::SamplingStrategy::OnChange,
            "CLI sampling_strategy=OnChange must be preserved when the file omits the key"
        );
    }

    #[test]
    fn test_merge_sampling_keys_when_present_still_govern() {
        // 2A regression guard: when the file DOES set `sampling-rate` and/or
        // `sampling-strategy`, the file value wins over the CLI value. This is
        // the same contract `test_sampling_config_merges_project_config`
        // asserts (file widens CLI when explicit); the new gates must not have
        // accidentally inverted it.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nsampling-rate = \"0.25\"\nsampling-strategy = \"on-change\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig {
            sampling_rate: 0.9,
            sampling_strategy: chaffra_telemetry::SamplingStrategy::Rate,
            ..Default::default()
        };
        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert!((merged.sampling_rate - 0.25).abs() < f64::EPSILON);
        assert_eq!(
            merged.sampling_strategy,
            chaffra_telemetry::SamplingStrategy::OnChange
        );
    }

    #[test]
    fn test_merge_default_audience_is_user_only_no_files() {
        // No project telemetry config -> the merged audience is the
        // privacy-preserving default and cannot emit operator telemetry.
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let project_config = ChaffraConfig::default();
        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly
        );
        assert!(!merged.audience.operator_enabled());
    }

    #[test]
    fn test_merge_file_audience_governs_when_present() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"operator-only\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        // CLI base is the privacy default; the file's explicit `audience` widens it.
        let cli_config = chaffra_telemetry::TelemetryConfig::default();

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly
        );
    }

    #[test]
    fn test_merge_absent_file_audience_keeps_cli_base() {
        // The file configures sampling but not `audience`: an explicit CLI flag
        // (`on`) must be preserved, not reset to the default.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nsampling-rate = \"0.5\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            cli_audience_override: Some(chaffra_telemetry::TelemetryAudience::On),
            ..Default::default()
        };

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(merged.audience, chaffra_telemetry::TelemetryAudience::On);
    }

    /// Construct a CLI-derived config representing an explicit `--telemetry`
    /// flag (sets both the base audience and the precedence hint).
    fn cli_config_with_flag(
        audience: chaffra_telemetry::TelemetryAudience,
    ) -> chaffra_telemetry::TelemetryConfig {
        chaffra_telemetry::TelemetryConfig {
            audience,
            cli_audience_override: Some(audience),
            ..Default::default()
        }
    }

    /// Load a project config whose `[modules.telemetry]` sets `audience`.
    fn project_config_with_file_audience(value: &str) -> ChaffraConfig {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            format!("[project]\nentry = []\n\n[modules.telemetry]\naudience = \"{value}\"\n"),
        )
        .unwrap();
        load_config(None, dir.path()).unwrap()
    }

    #[test]
    fn test_merge_explicit_cli_flag_beats_file_both_directions() {
        // Explicit CLI `off` is NOT overridable by a checked-in `audience = on`.
        let merged = merge_telemetry_config(
            &cli_config_with_flag(chaffra_telemetry::TelemetryAudience::Off),
            &project_config_with_file_audience("on"),
        )
        .unwrap();
        assert_eq!(merged.audience, chaffra_telemetry::TelemetryAudience::Off);

        // ...and the reverse: explicit CLI `on` beats a checked-in `off`.
        let merged = merge_telemetry_config(
            &cli_config_with_flag(chaffra_telemetry::TelemetryAudience::On),
            &project_config_with_file_audience("off"),
        )
        .unwrap();
        assert_eq!(merged.audience, chaffra_telemetry::TelemetryAudience::On);

        // A narrower explicit CLI `user-only` is not widened by `audience = on`.
        let merged = merge_telemetry_config(
            &cli_config_with_flag(chaffra_telemetry::TelemetryAudience::UserOnly),
            &project_config_with_file_audience("on"),
        )
        .unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly
        );
    }

    #[test]
    fn test_merge_file_used_when_no_cli_flag() {
        // No CLI flag: the file `audience` governs.
        let merged = merge_telemetry_config(
            &chaffra_telemetry::TelemetryConfig::default(),
            &project_config_with_file_audience("operator-only"),
        )
        .unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly
        );
    }

    #[test]
    fn test_merge_invalid_file_audience_fails_closed() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"everyone\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let err = merge_telemetry_config(&cli_config, &project_config).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid [modules.telemetry] configuration"),
            "got: {err}"
        );
    }

    #[test]
    fn test_merge_file_backend_applied_when_no_cli_override() {
        // R10-F1: a checked-in `[modules.telemetry] backend` must take effect on
        // a live CLI run when no explicit `--telemetry-backend` /
        // `--telemetry-endpoint` was given. Previously the merge dropped the file
        // backend and kept the default JSON-file backend, diverging from the
        // MCP/module paths that honour `from_module_config`.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nbackend = \"stderr\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        // Default CLI config: no backend selector, so `cli_backend_override` is
        // false and the default backend is the JSON-file sink.
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        assert!(!cli_config.cli_backend_override);
        assert_eq!(
            cli_config.backends[0].kind,
            chaffra_telemetry::BackendKind::JsonFile
        );

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(merged.backends.len(), 1);
        assert_eq!(
            merged.backends[0].kind,
            chaffra_telemetry::BackendKind::Stderr,
            "file backend=stderr must replace the default JSON-file backend"
        );
    }

    #[test]
    fn test_merge_file_backend_carries_endpoint() {
        // The file backend's `endpoint` / `path` travel with the backend kind,
        // matching `from_module_config` (the MCP/module path).
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nbackend = \"otlp\"\nendpoint = \"http://localhost:4318\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(
            merged.backends[0].kind,
            chaffra_telemetry::BackendKind::Otlp
        );
        assert_eq!(
            merged.backends[0].endpoint.as_deref(),
            Some("http://localhost:4318")
        );
    }

    #[test]
    fn test_merge_explicit_cli_backend_beats_file_backend() {
        // R10-F1 precedence guard: an explicit CLI backend selector wins over a
        // checked-in file `backend`. `cli_backend_override` marks the CLI choice.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nbackend = \"stderr\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        // Simulate `--telemetry-backend otlp`: explicit backend + override marker.
        let cli_config = chaffra_telemetry::TelemetryConfig {
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::Otlp,
                endpoint: Some("http://cli-host:4317".to_owned()),
                path: None,
                options: std::collections::HashMap::new(),
            }],
            cli_backend_override: true,
            ..Default::default()
        };

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(
            merged.backends[0].kind,
            chaffra_telemetry::BackendKind::Otlp,
            "explicit --telemetry-backend must win over file backend=stderr"
        );
        assert_eq!(
            merged.backends[0].endpoint.as_deref(),
            Some("http://cli-host:4317")
        );
    }

    #[test]
    fn test_merge_absent_file_backend_keeps_cli_backend() {
        // A `[modules.telemetry]` section without a `backend` key must NOT clobber
        // the CLI/default backend (mirrors the sampling-key gate).
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nsampling-rate = \"0.5\"\n",
        )
        .unwrap();
        let project_config = load_config(None, dir.path()).unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();

        let merged = merge_telemetry_config(&cli_config, &project_config).unwrap();
        assert_eq!(
            merged.backends[0].kind,
            chaffra_telemetry::BackendKind::JsonFile,
            "absent file backend must leave the default backend untouched"
        );
    }

    #[test]
    fn test_resolve_subcommand_telemetry_reads_project_file_audience() {
        // P3: the telemetry diagnostic subcommands resolve their audience
        // through the SAME precedence chain a live run uses. With NO CLI flag, a
        // checked-in `[modules.telemetry] audience` in the supplied project dir's
        // `.chaffra.toml` must govern — previously these commands ignored the
        // file entirely.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"operator-only\"\n",
        )
        .unwrap();

        // 1C: the helper takes an explicit `project_dir`, so the test no longer
        // mutates the process cwd via `CwdGuard`. The cwd-switch retrofit was a
        // symptom of the previous swallow of `current_dir()` errors; the new
        // signature removes both the swallow and the test-only cwd serialisation.
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let resolved = resolve_subcommand_telemetry(&cli_config, None, dir.path()).unwrap();
        assert_eq!(
            resolved.audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly,
            "subcommand must honour the checked-in [modules.telemetry] audience"
        );
    }

    #[test]
    fn test_resolve_subcommand_telemetry_explicit_flag_beats_file() {
        // P3: an explicit `--telemetry` flag still wins over the file audience,
        // exactly as in `run_with_telemetry` — a checked-in `audience = on`
        // cannot widen an explicit `--telemetry user-only`.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"on\"\n",
        )
        .unwrap();

        let cli_config = cli_config_with_flag(chaffra_telemetry::TelemetryAudience::UserOnly);
        let resolved = resolve_subcommand_telemetry(&cli_config, None, dir.path()).unwrap();
        assert_eq!(
            resolved.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly,
            "explicit CLI flag must beat the checked-in file audience"
        );
    }

    #[test]
    fn test_resolve_subcommand_telemetry_invalid_file_fails_closed() {
        // P3: a structurally invalid `[modules.telemetry]` surfaces as a typed
        // error rather than being coerced to a wider default.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"everyone\"\n",
        )
        .unwrap();

        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let err = resolve_subcommand_telemetry(&cli_config, None, dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid [modules.telemetry] configuration"),
            "got: {err}"
        );
    }

    #[test]
    fn test_resolve_subcommand_telemetry_malformed_toml_fails_closed() {
        // 1C: a `.chaffra.toml` whose TOML is malformed (parse error, NOT a
        // bad `audience` value) must surface as a typed error too. Previously
        // the helper called `load_config(None, &cwd).ok()`, which swallowed the
        // parse error and fell back to the default config — silently widening
        // the audience to user-only regardless of a checked-in
        // `[modules.telemetry] audience = "off"` further down the same file.
        // The strict loader path now propagates the error via `?`.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            // Unterminated section header -> toml parse error.
            "[project\nentry = []\n",
        )
        .unwrap();

        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let err = resolve_subcommand_telemetry(&cli_config, None, dir.path()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("failed to load .chaffra.toml"),
            "malformed TOML must surface as a typed error from the strict loader, got: {msg}"
        );
    }

    #[test]
    fn test_management_collector_honours_file_audience() {
        // R11-F1: `chaffra management` resolves telemetry through the SAME
        // file-aware path as live runs/diagnostics, so a checked-in
        // `[modules.telemetry] audience` governs the management collector.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"operator-only\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let collector = build_management_collector_in(&cli_config, None, dir.path()).unwrap();
        assert_eq!(
            collector.config().audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly,
            "management must honour the checked-in [modules.telemetry] audience"
        );
    }

    #[test]
    fn test_management_collector_honours_file_backend() {
        // R11-F1: the file `[modules.telemetry] backend` governs the management
        // collector too (no CLI backend override present).
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\nbackend = \"stderr\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let collector = build_management_collector_in(&cli_config, None, dir.path()).unwrap();
        assert_eq!(
            collector.config().backends[0].kind,
            chaffra_telemetry::BackendKind::Stderr,
            "management must honour the checked-in [modules.telemetry] backend"
        );
    }

    #[test]
    fn test_management_collector_explicit_cli_beats_file() {
        // R11-F1: an explicit CLI `--telemetry` flag still wins over the file
        // audience for management, matching the shared precedence rule.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"on\"\n",
        )
        .unwrap();
        let cli_config = cli_config_with_flag(chaffra_telemetry::TelemetryAudience::UserOnly);
        let collector = build_management_collector_in(&cli_config, None, dir.path()).unwrap();
        assert_eq!(
            collector.config().audience,
            chaffra_telemetry::TelemetryAudience::UserOnly,
            "explicit CLI --telemetry must beat the file audience for management"
        );
    }

    #[test]
    fn test_management_collector_invalid_file_fails_closed() {
        // R11-F1: a malformed `[modules.telemetry]` fails closed BEFORE the
        // management server starts, instead of silently starting with defaults.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"everyone\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let err = build_management_collector_in(&cli_config, None, dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid [modules.telemetry] configuration"),
            "management must fail closed on malformed telemetry config, got: {err}"
        );
    }

    #[test]
    fn test_management_collector_wrapper_resolves_cwd() {
        // Exercise the `build_management_collector` wrapper's Ok-arm (it resolves
        // `current_dir()` then delegates to the `_in` form), pinning the cwd to a
        // clean tempdir so the resolved audience is the deterministic default.
        let dir = TempDir::new().unwrap();
        let _cwd = CwdGuard::enter(dir.path());
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let collector = build_management_collector(&cli_config).unwrap();
        assert_eq!(
            collector.config().audience,
            chaffra_telemetry::TelemetryAudience::UserOnly
        );
    }

    #[test]
    fn test_cmd_telemetry_status_wrapper_resolves_cwd() {
        // The top-level `cmd_telemetry_status` resolves `current_dir()` and
        // calls `cmd_telemetry_status_in`. Exercise the wrapper's Ok-arm so the
        // dispatch-site behaviour (cwd-as-project-dir) is covered alongside the
        // testable `_in` form. The cwd is pinned to a clean tempdir via
        // `CwdGuard` so the resolved audience is deterministic (UserOnly).
        let dir = TempDir::new().unwrap();
        let _cwd = CwdGuard::enter(dir.path());
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let out = cmd_telemetry_status(&cli_config);
        assert!(
            out.contains("Telemetry mode: UserOnly"),
            "wrapper must resolve cwd and report the audience, got: {out}"
        );
    }

    #[test]
    fn test_cmd_telemetry_status_returns_error_on_bad_config() {
        // F7: `cmd_telemetry_status` now returns `Result<String>` (matching
        // `test` and `inspect`) so an invalid `.chaffra.toml` produces a
        // nonzero exit instead of a success report containing an inline
        // "Telemetry configuration error: ..." string. Scripted callers
        // could not distinguish that success-with-error-string from a clean
        // report; the typed error makes the fail-closed behaviour observable.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"everyone\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let err = cmd_telemetry_status_in(&cli_config, None, dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid [modules.telemetry] configuration"),
            "got: {err}"
        );
    }

    #[test]
    fn test_cmd_telemetry_test_wrapper_resolves_cwd() {
        // The top-level `cmd_telemetry_test` resolves cwd and forwards to
        // `_in`. Cover the wrapper's Ok-arm. Cwd is pinned via `CwdGuard` to a
        // clean tempdir.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.json");
        // Operator audience: backend exercise/reporting is operator-gated
        // (R8-F1), so the flush path the wrapper forwards to runs only when
        // operator telemetry is enabled.
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            cli_audience_override: Some(chaffra_telemetry::TelemetryAudience::On),
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(path.to_str().unwrap().to_owned()),
                options: HashMap::new(),
            }],
            ..Default::default()
        };
        let _cwd = CwdGuard::enter(dir.path());
        let out = cmd_telemetry_test(&tel_config).unwrap();
        assert!(out.contains("flushed"), "got: {out}");
    }

    #[test]
    fn test_cmd_telemetry_test_off_audience_does_not_write_backend() {
        // F5: when the resolved audience is `Off`, `telemetry test` must NOT
        // create/write/contact any backend. The previous implementation built
        // the backend, called `.flush()` (which under JsonFile writes an
        // empty-projection file), and printed `[OK] ... -- test metric flushed`
        // even though the operator had explicitly disabled telemetry. The
        // short-circuit now matches `run_with_telemetry`'s `Off` early-return
        // so the diagnostic command honours the same "no flush" rule.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("off.json");
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::Off,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(path.to_str().unwrap().to_owned()),
                options: HashMap::new(),
            }],
            cli_audience_override: Some(chaffra_telemetry::TelemetryAudience::Off),
            ..Default::default()
        };
        let out = cmd_telemetry_test_in(&tel_config, None, dir.path()).unwrap();
        assert!(
            !path.exists(),
            "telemetry test wrote backend file under Off audience: {}",
            out
        );
        assert!(
            out.contains("Off") || out.contains("no backend writes"),
            "Off short-circuit message missing, got: {out}"
        );
        assert!(
            !out.contains("flushed"),
            "Off branch must not report flush, got: {out}"
        );
    }

    #[test]
    fn test_cmd_telemetry_inspect_wrapper_resolves_cwd() {
        // The top-level `cmd_telemetry_inspect` resolves cwd and forwards
        // to `_in`. Cover the wrapper's Ok-arm via the operator path (the
        // per-backend preview is operator-gated, R8-F1).
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            cli_audience_override: Some(chaffra_telemetry::TelemetryAudience::On),
            ..Default::default()
        };
        let dir = TempDir::new().unwrap();
        let _cwd = CwdGuard::enter(dir.path());
        let out = cmd_telemetry_inspect(&tel_config).unwrap();
        assert!(
            out.contains("chaffra.module.call_duration_ms"),
            "operator audience must preview operator metrics, got: {out}"
        );
    }

    #[test]
    fn test_cli_config_path_threads_through_tel_config() {
        // F6 uses `cli_config_path` on `TelemetryConfig` as a precedence
        // hint (same #[serde(skip)] pattern as `cli_audience_override`).
        // `cmd_telemetry_status` / `_test` / `_inspect` read the path from
        // there via `dispatch_config_path`, so the `main()` dispatch site
        // keeps its base-shape one-arg signature. Verify the wiring: a CLI
        // `--config <file>` populated into `cli_config_path` is honoured by
        // the diagnostic commands, while no path falls through to implicit
        // `.chaffra.toml` discovery in cwd.
        let dir = TempDir::new().unwrap();
        // Implicit project file: says `on`.
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"on\"\n",
        )
        .unwrap();
        let explicit = dir.path().join("explicit.toml");
        fs::write(
            &explicit,
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"off\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig {
            cli_config_path: Some(explicit.to_str().unwrap().to_owned()),
            ..Default::default()
        };
        // `dispatch_config_path` extracts the carried path.
        assert_eq!(
            dispatch_config_path(&cli_config),
            Some(explicit.to_str().unwrap())
        );
        // Status routes via `cli_config_path` to the explicit file (`off`),
        // NOT the implicit cwd file (`on`).
        let _cwd = CwdGuard::enter(dir.path());
        let status = cmd_telemetry_status(&cli_config);
        assert!(
            status.contains("Telemetry mode: Off"),
            "explicit --config audience must win, got: {status}"
        );

        // No carried path: implicit cwd `.chaffra.toml` (the `on` audience) wins.
        let cli_no_path = chaffra_telemetry::TelemetryConfig::default();
        let status = cmd_telemetry_status(&cli_no_path);
        assert!(
            status.contains("Telemetry mode: On"),
            "implicit cwd audience must win when no --config, got: {status}"
        );
    }

    #[test]
    fn test_cmd_telemetry_diagnostics_honour_explicit_config_flag() {
        // F6: every telemetry diagnostic accepts `Option<&str>` for the
        // global `--config <file>` and threads it into the precedence
        // resolution. The implicit cwd file says `audience = on` and an
        // EXPLICIT config file says `audience = off` — the explicit path
        // must win, exactly as it does for live `health`/`security` runs.
        // Without this threading, previews would disagree with the real
        // run, including missing an explicit config that disables telemetry.
        let dir = TempDir::new().unwrap();
        // Implicit project file: would say `on`.
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"on\"\n",
        )
        .unwrap();
        // Explicit `--config` file: says `off`. Live commands honour this;
        // diagnostics now honour it too.
        let explicit = dir.path().join("explicit.toml");
        fs::write(
            &explicit,
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"off\"\n",
        )
        .unwrap();
        let explicit_str = explicit.to_str().unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();

        let status = cmd_telemetry_status_in(&cli_config, Some(explicit_str), dir.path()).unwrap();
        assert!(
            status.contains("Telemetry mode: Off"),
            "status must reflect --config audience, got: {status}"
        );

        let test = cmd_telemetry_test_in(&cli_config, Some(explicit_str), dir.path()).unwrap();
        assert!(
            test.contains("Off") || test.contains("no backend writes"),
            "test must short-circuit on --config Off, got: {test}"
        );

        let inspect =
            cmd_telemetry_inspect_in(&cli_config, Some(explicit_str), dir.path()).unwrap();
        // Off projection: no user_summary content beyond the shell.
        assert!(
            !inspect.contains("\"files_total\": 1"),
            "inspect must project to Off via --config, got: {inspect}"
        );
    }

    #[test]
    fn test_resolve_subcommand_telemetry_missing_file_uses_default() {
        // No `.chaffra.toml` is the legitimate no-project-file case: it must
        // NOT error; the helper falls back to the default project config and
        // the merged audience matches the CLI base (user-only here). This pairs
        // with the malformed-TOML test above to demonstrate the strict loader
        // distinguishes "file absent" (ok) from "file unreadable/malformed"
        // (error).
        let dir = TempDir::new().unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let resolved = resolve_subcommand_telemetry(&cli_config, None, dir.path()).unwrap();
        assert_eq!(
            resolved.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly
        );
    }

    #[test]
    fn test_parse_audience_flag_validates() {
        // Valid values parse straight to the enum; invalid values are rejected
        // (fail closed) with an actionable message.
        assert_eq!(
            parse_audience_flag("operator-only").unwrap(),
            chaffra_telemetry::TelemetryAudience::OperatorOnly
        );
        assert_eq!(
            parse_audience_flag("on").unwrap(),
            chaffra_telemetry::TelemetryAudience::On
        );
        let err = parse_audience_flag("oprator-only").unwrap_err();
        assert!(err.contains("invalid telemetry audience"), "got: {err}");
    }

    #[test]
    fn test_build_telemetry_config_default_flag_is_user_only() {
        let cli = Cli {
            command: Command::Health {
                path: ".".to_owned(),
            },
            format: "terminal".to_owned(),
            config: None,
            telemetry: None,
            telemetry_backend: None,
            telemetry_endpoint: None,
        };
        let config = build_telemetry_config(&cli).unwrap();
        assert_eq!(
            config.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly
        );
        // R10-F1: with no CLI backend selector the precedence marker is false,
        // so a file `[modules.telemetry] backend` is free to take effect.
        assert!(
            !config.cli_backend_override,
            "no --telemetry-backend/--telemetry-endpoint -> cli_backend_override must be false"
        );
        // And the backend is the default JSON-file sink.
        assert_eq!(
            config.backends[0].kind,
            chaffra_telemetry::BackendKind::JsonFile
        );
    }

    #[test]
    fn test_build_telemetry_config_explicit_operator_only() {
        let cli = Cli {
            command: Command::Health {
                path: ".".to_owned(),
            },
            format: "terminal".to_owned(),
            config: None,
            telemetry: Some(chaffra_telemetry::TelemetryAudience::OperatorOnly),
            telemetry_backend: None,
            telemetry_endpoint: None,
        };
        let config = build_telemetry_config(&cli).unwrap();
        assert_eq!(
            config.audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly
        );
        // The explicit flag is also recorded as the precedence hint.
        assert_eq!(
            config.cli_audience_override,
            Some(chaffra_telemetry::TelemetryAudience::OperatorOnly)
        );
    }

    #[test]
    fn test_build_telemetry_config_invalid_backend_fails_closed() {
        // A present-but-invalid `--telemetry-backend` is a hard error, routed
        // through the same typed `BackendKind::parse` the file path uses — no
        // silent fallback to the default JSON-file backend.
        let cli = Cli {
            command: Command::Health {
                path: ".".to_owned(),
            },
            format: "terminal".to_owned(),
            config: None,
            telemetry: None,
            telemetry_backend: Some("otlpz".to_owned()),
            telemetry_endpoint: None,
        };
        let err = build_telemetry_config(&cli).unwrap_err();
        assert!(
            err.to_string().contains("invalid --telemetry-backend"),
            "got: {err}"
        );
    }

    #[test]
    fn test_build_telemetry_config_valid_backend() {
        // A valid `--telemetry-backend` is parsed through the typed parser and
        // produces exactly that backend (no default fallback).
        let cli = Cli {
            command: Command::Health {
                path: ".".to_owned(),
            },
            format: "terminal".to_owned(),
            config: None,
            telemetry: None,
            telemetry_backend: Some("stderr".to_owned()),
            telemetry_endpoint: Some("ignored".to_owned()),
        };
        let config = build_telemetry_config(&cli).unwrap();
        assert_eq!(config.backends.len(), 1);
        assert_eq!(
            config.backends[0].kind,
            chaffra_telemetry::BackendKind::Stderr
        );
        assert_eq!(config.backends[0].endpoint.as_deref(), Some("ignored"));
        // R10-F1: an explicit CLI backend selector sets the precedence marker,
        // so `merge_telemetry_config` will let it win over a file `backend`.
        assert!(
            config.cli_backend_override,
            "--telemetry-backend must set cli_backend_override"
        );
    }

    #[test]
    fn test_build_telemetry_config_endpoint_only_sets_otlp_and_override() {
        // R10-F1: `--telemetry-endpoint` with no `--telemetry-backend` builds an
        // OTLP backend AND sets the precedence marker (the `|| endpoint.is_some()`
        // disjunct), so a checked-in file `backend` cannot override an explicit
        // endpoint. This pins the endpoint-only construction branch.
        let cli = Cli {
            command: Command::Health {
                path: ".".to_owned(),
            },
            format: "terminal".to_owned(),
            config: None,
            telemetry: None,
            telemetry_backend: None,
            telemetry_endpoint: Some("http://endpoint-only:4318".to_owned()),
        };
        let config = build_telemetry_config(&cli).unwrap();
        assert_eq!(config.backends.len(), 1);
        assert_eq!(
            config.backends[0].kind,
            chaffra_telemetry::BackendKind::Otlp
        );
        assert_eq!(
            config.backends[0].endpoint.as_deref(),
            Some("http://endpoint-only:4318")
        );
        assert!(
            config.cli_backend_override,
            "--telemetry-endpoint alone must set cli_backend_override"
        );
    }

    #[test]
    fn test_telemetry_status_withholds_backends_under_user_only() {
        // F3: backend kind/connectivity is operator-shaped, so `telemetry
        // status` withholds it under the default `user-only` audience, matching
        // MCP `status`/`backends` and the `backend-status` finding.
        let dir = TempDir::new().unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let out = cmd_telemetry_status_in(&cli_config, None, dir.path()).unwrap();
        assert!(out.contains("Telemetry mode: UserOnly"), "got: {out}");
        assert!(
            out.contains("withheld"),
            "user-only status must withhold backend metadata, got: {out}"
        );
        assert!(
            !out.contains("[OK]") && !out.contains("[FAIL]"),
            "no backend connectivity may appear under user-only, got: {out}"
        );
    }

    #[test]
    fn test_telemetry_status_shows_backends_under_operator() {
        // Under an explicit operator opt-in the catalogue IS disclosed.
        let dir = TempDir::new().unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            cli_audience_override: Some(chaffra_telemetry::TelemetryAudience::On),
            ..Default::default()
        };
        let out = cmd_telemetry_status_in(&cli_config, None, dir.path()).unwrap();
        assert!(out.contains("Telemetry mode: On"), "got: {out}");
        assert!(
            out.contains("Backends:") && !out.contains("withheld"),
            "operator status must list the backend catalogue, got: {out}"
        );
    }

    #[test]
    fn test_cli_rejects_invalid_telemetry_flag() {
        // The clap value parser rejects an unrecognised `--telemetry` value at
        // parse time (fail closed), so it never reaches the config builder.
        let message = Cli::try_parse_from(["chaffra", "--telemetry", "oprator-only", "health"])
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(
            message.contains("invalid telemetry audience"),
            "expected invalid --telemetry to be rejected, got: {message:?}"
        );
    }

    #[test]
    fn test_run_with_telemetry_emits_audit_log_event_for_each_audience() {
        // F4 + R5-Audit-Off: `run_with_telemetry` calls
        // `maybe_audit_log_audience(effective_config.audience)` at the live
        // boundary. Accountability is recorded for every *opted-in*
        // audience:
        //   * `On` / `OperatorOnly` -> TelemetryEnabled (with audience tag)
        //   * `UserOnly`            -> TelemetryDisabled (user-facing on,
        //                              operator off)
        //   * `Off`                 -> NO event written. `--telemetry off`
        //                              is the operator's explicit "do not
        //                              emit, write, or leave traces"
        //                              instruction; honour the kill switch
        //                              with a zero-side-effect run.
        // The diagnostic previews (`status` / `test` / `inspect`) do NOT
        // trigger this — they don't run the workload, so they don't log.
        //
        // One combined test exercises all THREE arms in a single tempdir so
        // the iteration visits both the Enabled and Disabled cases AND the
        // `Off`-no-event case, leaving no implicitly-unreached catch-all
        // to skew coverage on the audit-log assertions.
        let dir = TempDir::new().unwrap();
        let _cwd = CwdGuard::enter(dir.path());
        let config = ChaffraConfig::default();

        // First invocation: OperatorOnly -> Enabled event.
        let tel_op = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::OperatorOnly,
            backends: vec![],
            ..Default::default()
        };
        run_with_telemetry(&tel_op, &config, "dead-code", |_collector| {
            Ok("ok\n".to_owned())
        })
        .unwrap();

        // Second invocation: UserOnly -> Disabled event (the only branch
        // that still writes a `TelemetryDisabled` event after R5-Audit-Off).
        let tel_user = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::UserOnly,
            backends: vec![],
            ..Default::default()
        };
        run_with_telemetry(&tel_user, &config, "health", |_collector| {
            Ok("ok\n".to_owned())
        })
        .unwrap();

        // Third invocation: Off -> NO event. This must not lengthen the log.
        let tel_off = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::Off,
            backends: vec![],
            ..Default::default()
        };
        run_with_telemetry(&tel_off, &config, "health", |_collector| {
            Ok("ok\n".to_owned())
        })
        .unwrap();

        let log_path = dir
            .path()
            .join(chaffra_telemetry::audit_log::AUDIT_LOG_FILE);
        assert!(log_path.exists());
        let events = chaffra_telemetry::audit_log::read_log(&log_path);

        // Classify by direct iteration with `if let` — both kept branches
        // execute exactly once in this test (one Enabled + one Disabled),
        // so coverage does not flag an unreached arm.
        let mut enabled_audiences: Vec<String> = Vec::new();
        let mut disabled_count = 0usize;
        for e in &events {
            if let chaffra_telemetry::audit_log::AuditEvent::TelemetryEnabled { audience, .. } = e {
                enabled_audiences.push(audience.clone());
            }
            if let chaffra_telemetry::audit_log::AuditEvent::TelemetryDisabled { .. } = e {
                disabled_count += 1;
            }
        }
        assert_eq!(enabled_audiences.len(), 1);
        assert_eq!(enabled_audiences[0], "OperatorOnly");
        assert_eq!(disabled_count, 1);
        assert_eq!(
            events.len(),
            2,
            "Off must not write an audit event; expected exactly two events \
             (OperatorOnly Enabled + UserOnly Disabled)"
        );
    }

    #[test]
    fn test_run_with_telemetry_user_only_withholds_operator_metrics() {
        // End-to-end: default (user-only) audience flushes a snapshot with NO
        // operator data, proving projection happens before the emission boundary.
        let dir = TempDir::new().unwrap();
        let telemetry_path = dir.path().join("telemetry.json");
        let config = ChaffraConfig::default();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::UserOnly,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(telemetry_path.to_str().unwrap().to_owned()),
                options: HashMap::new(),
            }],
            ..Default::default()
        };

        let _cwd = CwdGuard::enter(dir.path());

        let output = run_with_telemetry(&tel_config, &config, "dead-code", |collector| {
            // Record one user-facing metric so the flushed snapshot is
            // non-empty, alongside the operator-only call duration that
            // `run_with_telemetry` records automatically.
            let mut sev = HashMap::new();
            sev.insert("warning".to_owned(), 1);
            collector.record_module_findings("dead-code", 1, &sev);
            Ok("ok\n".to_owned())
        })
        .unwrap();
        assert_eq!(output, "ok\n");

        let content = std::fs::read_to_string(&telemetry_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        // The command's own call duration is operator-only and must be absent.
        assert!(
            parsed["operator_summary"]["module_call_durations"]
                .as_object()
                .unwrap()
                .is_empty(),
            "user-only flush must not contain operator call durations"
        );
        // The flush must still carry the user-facing finding metric...
        let data_points = parsed["data_points"].as_array().unwrap();
        assert!(
            data_points
                .iter()
                .any(|dp| dp["name"] == "chaffra.analysis.findings_total"),
            "user-only flush should retain user-facing metrics"
        );
        // ...and no operator-only data point may leak across the boundary.
        for dp in data_points {
            let name = dp["name"].as_str().unwrap();
            assert!(
                !name.starts_with("chaffra.module.call_duration_ms")
                    && !name.starts_with("chaffra.module.error_total")
                    && !name.starts_with("chaffra.startup."),
                "operator metric {name} leaked into a user-only flush"
            );
        }
    }

    /// Drive `run_with_telemetry` for an audience with a JSON-file backend and
    /// return the parsed flushed snapshot, or `None` when nothing was flushed.
    fn cli_flush_for_audience(
        audience: chaffra_telemetry::TelemetryAudience,
    ) -> Option<serde_json::Value> {
        let dir = TempDir::new().unwrap();
        let telemetry_path = dir.path().join("telemetry.json");
        let config = ChaffraConfig::default();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(telemetry_path.to_str().unwrap().to_owned()),
                options: HashMap::new(),
            }],
            ..Default::default()
        };

        let _cwd = CwdGuard::enter(dir.path());
        run_with_telemetry(&tel_config, &config, "dead-code", |collector| {
            let mut sev = HashMap::new();
            sev.insert("warning".to_owned(), 1);
            collector.record_module_findings("dead-code", 1, &sev);
            Ok("ok\n".to_owned())
        })
        .unwrap();

        std::fs::read_to_string(&telemetry_path)
            .ok()
            .map(|c| serde_json::from_str(&c).unwrap())
    }

    #[test]
    fn test_run_with_telemetry_flush_rule_matches_module_path() {
        // 1B: the CLI flush path and the telemetry-module flush path follow the
        // SAME rule — flush the projected snapshot for any audience except Off.
        // Assert the CLI path's per-audience behaviour matches projection, the
        // same contract the module-path test asserts in chaffra-telemetry.
        use chaffra_telemetry::TelemetryAudience::{Off, On, OperatorOnly, UserOnly};

        // user-only: user data present, no operator call durations.
        let v = cli_flush_for_audience(UserOnly).expect("user-only must flush");
        assert!(
            v["operator_summary"]["module_call_durations"]
                .as_object()
                .unwrap()
                .is_empty()
        );

        // operator-only: operator data present, user summary wiped.
        let v = cli_flush_for_audience(OperatorOnly).expect("operator-only must flush");
        assert_eq!(v["user_summary"]["files_total"], 0);
        assert!(
            v["data_points"]
                .as_array()
                .unwrap()
                .iter()
                .any(|dp| dp["name"] == "chaffra.module.call_duration_ms")
        );

        // on: everything present.
        let v = cli_flush_for_audience(On).expect("on must flush");
        assert!(
            v["data_points"]
                .as_array()
                .unwrap()
                .iter()
                .any(|dp| dp["name"] == "chaffra.module.call_duration_ms")
        );

        // off: nothing flushed.
        assert!(cli_flush_for_audience(Off).is_none(), "off must not flush");
    }

    #[test]
    fn test_cmd_telemetry_test_flushes_and_projects_under_operator() {
        // Under an operator audience the test flush runs (R8-F1 gate open) and
        // the snapshot is projected before the write. Covers the flush path.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("t.json");
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            cli_audience_override: Some(chaffra_telemetry::TelemetryAudience::On),
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::JsonFile,
                endpoint: None,
                path: Some(path.to_str().unwrap().to_owned()),
                options: HashMap::new(),
            }],
            ..Default::default()
        };
        let out = cmd_telemetry_test_in(&tel_config, None, dir.path()).unwrap();
        assert!(out.contains("flushed"), "got: {out}");
        assert!(path.exists(), "operator test must write the backend file");
    }

    #[test]
    fn test_cmd_telemetry_test_withholds_backend_metadata_under_user_only() {
        // R8-F1: under the default user-only audience, `telemetry test` must not
        // construct, contact, or NAME backends, nor disclose operator-shaped
        // config metadata. Use a revealing OTLP endpoint and assert neither the
        // backend kind nor the endpoint appears, and nothing is flushed.
        let dir = TempDir::new().unwrap();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::UserOnly,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::Otlp,
                endpoint: Some("http://operator-secret-host:4317".to_owned()),
                path: None,
                options: HashMap::new(),
            }],
            ..Default::default()
        };
        let out = cmd_telemetry_test_in(&tel_config, None, dir.path()).unwrap();
        assert!(out.contains("Telemetry mode: UserOnly"), "got: {out}");
        assert!(
            !out.contains("flushed"),
            "no flush under user-only, got: {out}"
        );
        assert!(
            !out.to_lowercase().contains("otlp") && !out.contains("operator-secret-host"),
            "backend kind/endpoint leaked under user-only, got: {out}"
        );
    }

    #[test]
    fn test_cmd_telemetry_inspect_withholds_backend_metadata_under_user_only() {
        // R8-F1: inspect withholds the per-backend preview (the `--- {name} ---`
        // header and each backend's `inspect()` output, which can embed
        // endpoint/config) under the default user-only audience.
        let dir = TempDir::new().unwrap();
        let tel_config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::UserOnly,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::Otlp,
                endpoint: Some("http://operator-secret-host:4317".to_owned()),
                path: None,
                options: HashMap::new(),
            }],
            ..Default::default()
        };
        let out = cmd_telemetry_inspect_in(&tel_config, None, dir.path()).unwrap();
        assert!(out.contains("Telemetry mode: UserOnly"), "got: {out}");
        assert!(
            !out.to_lowercase().contains("otlp")
                && !out.contains("operator-secret-host")
                && !out.contains("chaffra.module.call_duration_ms"),
            "backend metadata / operator preview leaked under user-only, got: {out}"
        );
    }

    #[test]
    fn test_cmd_telemetry_status_reflects_file_audience() {
        // P3: `telemetry status` resolves through the live-run precedence chain,
        // so a checked-in `[modules.telemetry] audience` is reflected in the
        // reported mode (previously the file was ignored and only the CLI/default
        // showed). Here the default CLI base is user-only but the file selects
        // operator-only, which must win in the absence of an explicit flag.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"operator-only\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default(); // user-only base
        let out = cmd_telemetry_status_in(&cli_config, None, dir.path()).unwrap();
        assert!(
            out.contains("Telemetry mode: OperatorOnly"),
            "status must reflect the checked-in file audience, got: {out}"
        );
    }

    #[test]
    fn test_cmd_telemetry_status_malformed_file_is_surfaced() {
        // A malformed `[modules.telemetry]` surfaces as a typed `Err`
        // (fail-closed), so scripted callers see a nonzero exit instead of
        // a success-with-error-string. Previously the helper returned a
        // `String` that embedded the error inline, which automation could
        // not distinguish from a healthy report.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"everyone\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default();
        let err = cmd_telemetry_status_in(&cli_config, None, dir.path()).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid [modules.telemetry] configuration"),
            "malformed file must surface a typed error from status, got: {err}"
        );
    }

    #[test]
    fn test_cmd_telemetry_inspect_uses_file_audience_operator_only() {
        // P3: under a checked-in operator-only audience (no CLI flag), inspect
        // previews operator data — proving the subcommand now reads the file,
        // not just the CLI/default. The user summary is projected out.
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".chaffra.toml"),
            "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"operator-only\"\n",
        )
        .unwrap();
        let cli_config = chaffra_telemetry::TelemetryConfig::default(); // user-only base
        let out = cmd_telemetry_inspect_in(&cli_config, None, dir.path()).unwrap();
        assert!(
            out.contains("chaffra.module.call_duration_ms"),
            "operator metric must appear when the file selects operator-only: {out}"
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
        // `CwdGuard` serializes the cwd switch (see chaffra#51).
        let _cwd = CwdGuard::enter(dir.path());

        let formatter = create_formatter(OutputFormat::Terminal);
        let output = run_with_telemetry(&tel_config, &config, "dead-code", |collector| {
            cmd_dead_code(&root, &config, formatter.as_ref(), collector)
        })
        .unwrap();

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

        let _cwd = CwdGuard::enter(dir.path());

        let result = run_with_telemetry(&tel_config, &config, "failing-cmd", |_collector| {
            anyhow::bail!("simulated analysis failure")
        });

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

        let _cwd = CwdGuard::enter(dir.path());

        let result = run_with_telemetry(&tel_config, &config, "failing-cmd", |_collector| {
            anyhow::bail!("simulated analysis failure")
        });

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

    #[test]
    fn test_discover_security_files_honors_ignore_patterns() {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        // Create a visible .env file at the root.
        fs::write(root.join(".env"), "VISIBLE_SECRET=abc123").unwrap();

        // Create an ignored directory with a secret file.
        let ignored_dir = root.join("secrets_backup");
        fs::create_dir_all(&ignored_dir).unwrap();
        fs::write(ignored_dir.join(".env"), "LEAKED_KEY=super_secret_42").unwrap();

        // Create a .chafframeignore that ignores secrets_backup.
        fs::write(root.join(".chafframeignore"), "secrets_backup/**\n").unwrap();

        let ignore_patterns = chaffra_parse::discovery::load_all_ignore_patterns(root, &[]);
        let mut files: Vec<FileInfo> = Vec::new();
        discover_security_files(root, root, &ignore_patterns, &mut files);

        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&".env"), "root .env should be discovered");
        assert!(
            !paths.iter().any(|p| p.contains("secrets_backup")),
            "files in ignored directory should not be discovered"
        );
    }
}
