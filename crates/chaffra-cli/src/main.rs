//! chaffra -- codebase intelligence CLI.

use anyhow::{Context, Result};
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::{CONFIG_FILE_NAME, CONFIG_TEMPLATE, ChaffraConfig};
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::module::ModuleHost;
use chaffra_deadcode::DeadCodeModule;
use chaffra_output::{OutputFormat, create_formatter};
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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let format = OutputFormat::from_str_loose(&cli.format).unwrap_or(OutputFormat::Terminal);
    let formatter = create_formatter(format);

    match cli.command {
        Command::Health { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            let files = discover_and_read_files(&root, &config);

            if files.is_empty() {
                println!("No source files found.");
                return Ok(());
            }

            let health = chaffra_complexity::analyze_project_health(
                &files,
                config.health.max_cyclomatic,
                config.health.max_cognitive,
            )?;

            print!("{}", formatter.format_health(&health));
        }

        Command::DeadCode { path } => {
            let root = Path::new(&path).canonicalize().context("invalid path")?;
            let config = load_config(cli.config.as_deref(), &root)?;
            let files = discover_and_read_files(&root, &config);

            if files.is_empty() {
                println!("No source files found.");
                return Ok(());
            }

            let host = build_module_host();
            let result = host.analyze("dead-code", &files, &config)?;
            print!("{}", formatter.format_findings(&result.findings));
        }

        Command::Dupes { .. } => {
            println!("not yet implemented");
        }

        Command::Audit { .. } => {
            println!("not yet implemented");
        }

        Command::Watch { .. } => {
            println!("not yet implemented");
        }

        Command::Fix { .. } => {
            println!("not yet implemented");
        }

        Command::Explain { id } => {
            let host = build_module_host();
            match host.explain(&id) {
                Ok(explanation) => {
                    println!("Rule: {} ({})", explanation.name, explanation.rule_id);
                    println!();
                    println!("{}", explanation.description);
                    println!();
                    println!("Rationale: {}", explanation.rationale);
                    println!("Default severity: {}", explanation.default_severity);
                    println!("Suppress with: {}", explanation.suppression_syntax);
                    if !explanation.examples.is_empty() {
                        println!();
                        println!("Examples:");
                        for example in &explanation.examples {
                            println!("  {example}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Command::Init => {
            let config_path = Path::new(CONFIG_FILE_NAME);
            if config_path.exists() {
                eprintln!("{CONFIG_FILE_NAME} already exists");
                std::process::exit(1);
            }
            std::fs::write(config_path, CONFIG_TEMPLATE)
                .context("failed to write configuration file")?;
            println!("Created {CONFIG_FILE_NAME}");
        }

        Command::Modules => {
            let host = build_module_host();
            let modules = host.list();
            if modules.is_empty() {
                println!("No modules registered.");
                return Ok(());
            }
            for info in modules {
                println!("{} v{} - {}", info.id, info.version, info.name);
                println!("  Languages: {}", info.languages.join(", "));
                println!("  Capabilities: {}", info.capabilities.join(", "));
                println!(
                    "  Rules: {}",
                    info.rules
                        .iter()
                        .map(|r| r.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!();
            }
        }
    }

    Ok(())
}
