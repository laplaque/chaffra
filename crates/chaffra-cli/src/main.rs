//! chaffra -- codebase intelligence CLI.

use anyhow::{Context, Result};
use chaffra_ai_quality::AiQualityModule;
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::{CONFIG_FILE_NAME, CONFIG_TEMPLATE, ChaffraConfig};
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::module::ModuleHost;
use chaffra_deadcode::DeadCodeModule;
use chaffra_frameworks::FrameworksModule;
use chaffra_llm_defense::LlmDefenseModule;
use chaffra_output::{OutputFormat, create_formatter};
use chaffra_security::SecurityModule;
use clap::{Parser, Subcommand};
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
}

fn build_module_host() -> ModuleHost {
    let mut host = ModuleHost::new();
    // Register built-in modules.
    let _ = host.register(Box::new(DeadCodeModule::new()));
    let _ = host.register(Box::new(ComplexityModule::new()));
    let _ = host.register(Box::new(SecurityModule::new()));
    let _ = host.register(Box::new(FrameworksModule::new()));
    let _ = host.register(Box::new(AiQualityModule::new()));
    let _ = host.register(Box::new(LlmDefenseModule::new()));
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

fn cmd_ai_quality(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host();
    let result = host.analyze("ai-quality", &files, config)?;
    Ok(formatter.format_findings(&result.findings))
}

fn cmd_llm_defense(
    root: &Path,
    config: &ChaffraConfig,
    formatter: &dyn chaffra_output::Formatter,
) -> Result<String> {
    let files = discover_and_read_files(root, config);
    if files.is_empty() {
        return Ok("No source files found.\n".to_owned());
    }
    let host = build_module_host();
    let result = host.analyze("llm-defense", &files, config)?;
    Ok(formatter.format_findings(&result.findings))
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

        Command::AiQuality { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!("{}", cmd_ai_quality(&root, &config, formatter.as_ref())?);
        }

        Command::LlmDefense { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            print!("{}", cmd_llm_defense(&root, &config, formatter.as_ref())?);
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

        Command::Fix { .. } => {
            print!("{}", cmd_stub("fix"));
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
        assert_eq!(modules.len(), 6);
        let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
        assert!(ids.contains(&"dead-code"));
        assert!(ids.contains(&"complexity"));
        assert!(ids.contains(&"security"));
        assert!(ids.contains(&"frameworks"));
        assert!(ids.contains(&"ai-quality"));
        assert!(ids.contains(&"llm-defense"));
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
        // Output should mention a health score or grade.
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
        // Should find the 'unused' function.
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
        // JSON output should be valid JSON.
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

    #[test]
    fn test_cmd_stub_fix() {
        assert_eq!(cmd_stub("fix"), "not yet implemented\n");
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
        assert!(
            output.contains("ai-quality"),
            "should list ai-quality module"
        );
        assert!(
            output.contains("llm-defense"),
            "should list llm-defense module"
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

    // --- cmd_ai_quality tests ---

    #[test]
    fn test_cmd_ai_quality_fixtures() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/python/ai-quality");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_ai_quality(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_ai_quality_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_ai_quality(dir.path(), &config, formatter.as_ref()).unwrap();
        assert_eq!(output, "No source files found.\n");
    }

    // --- cmd_llm_defense tests ---

    #[test]
    fn test_cmd_llm_defense_fixtures() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/python/llm-defense");
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_llm_defense(&root, &config, formatter.as_ref()).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_cmd_llm_defense_empty_dir() {
        let dir = TempDir::new().unwrap();
        let config = ChaffraConfig::default();
        let formatter = create_formatter(OutputFormat::Terminal);
        let output = cmd_llm_defense(dir.path(), &config, formatter.as_ref()).unwrap();
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
}
