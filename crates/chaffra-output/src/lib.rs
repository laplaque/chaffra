//! Output formatters for analysis results.
//!
//! Provides JSON, Markdown, and terminal formatters implementing a common
//! `Formatter` trait.

use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};

pub mod json;
pub mod markdown;
pub mod terminal;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Markdown,
    Terminal,
}

impl OutputFormat {
    /// Parse from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(OutputFormat::Json),
            "markdown" | "md" => Some(OutputFormat::Markdown),
            "terminal" | "text" => Some(OutputFormat::Terminal),
            _ => None,
        }
    }
}

/// Common interface for output formatters.
pub trait Formatter {
    /// Format analysis findings.
    fn format_findings(&self, findings: &[Finding]) -> String;

    /// Format a project health report.
    fn format_health(&self, health: &ProjectHealth) -> String;

    /// Format a full analysis result (findings + metrics).
    fn format_result(&self, result: &AnalysisResult, health: Option<&ProjectHealth>) -> String;
}

/// Create a formatter for the given output format.
pub fn create_formatter(format: OutputFormat) -> Box<dyn Formatter> {
    match format {
        OutputFormat::Json => Box::new(json::JsonFormatter),
        OutputFormat::Markdown => Box::new(markdown::MarkdownFormatter),
        OutputFormat::Terminal => Box::new(terminal::TerminalFormatter),
    }
}

/// Severity icon for terminal/markdown display.
pub fn severity_icon(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "[E]",
        Severity::Warning => "[W]",
        Severity::Info => "[I]",
    }
}
