//! chaffra — codebase intelligence CLI.

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// Explain a specific diagnostic finding in plain language.
    Explain {
        /// Diagnostic ID to explain (e.g. "dead-code:unused-function").
        id: String,
    },
    /// Initialise a `.chaffra.toml` configuration file in the current directory.
    Init,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Health { .. } => {
            println!("not yet implemented");
        }
        Command::DeadCode { .. } => {
            println!("not yet implemented");
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
        Command::Explain { .. } => {
            println!("not yet implemented");
        }
        Command::Init => {
            println!("not yet implemented");
        }
    }

    Ok(())
}
