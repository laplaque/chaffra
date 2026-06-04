//! Output formatters for analysis results.
//!
//! Provides JSON, Markdown, terminal, PR comment, GitHub Actions annotations,
//! and CodeClimate formatters implementing a common `Formatter` trait.

use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};

pub mod annotations;
pub mod codeclimate;
pub mod json;
pub mod markdown;
pub mod pr_comment;
pub mod terminal;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Markdown,
    Terminal,
    PrComment,
    Annotations,
    CodeClimate,
}

impl OutputFormat {
    /// Parse from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(OutputFormat::Json),
            "markdown" | "md" => Some(OutputFormat::Markdown),
            "terminal" | "text" => Some(OutputFormat::Terminal),
            "pr-comment" | "pr_comment" | "prcomment" | "github" => Some(OutputFormat::PrComment),
            "annotations" | "actions" => Some(OutputFormat::Annotations),
            "codeclimate" | "code-climate" | "code_climate" | "gitlab" => {
                Some(OutputFormat::CodeClimate)
            }
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
        OutputFormat::PrComment => Box::new(pr_comment::PrCommentFormatter),
        OutputFormat::Annotations => Box::new(annotations::AnnotationsFormatter),
        OutputFormat::CodeClimate => Box::new(codeclimate::CodeClimateFormatter),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_from_str_loose() {
        let cases = vec![
            ("json", Some(OutputFormat::Json)),
            ("JSON", Some(OutputFormat::Json)),
            ("markdown", Some(OutputFormat::Markdown)),
            ("md", Some(OutputFormat::Markdown)),
            ("terminal", Some(OutputFormat::Terminal)),
            ("text", Some(OutputFormat::Terminal)),
            ("pr-comment", Some(OutputFormat::PrComment)),
            ("pr_comment", Some(OutputFormat::PrComment)),
            ("prcomment", Some(OutputFormat::PrComment)),
            ("github", Some(OutputFormat::PrComment)),
            ("annotations", Some(OutputFormat::Annotations)),
            ("actions", Some(OutputFormat::Annotations)),
            ("codeclimate", Some(OutputFormat::CodeClimate)),
            ("code-climate", Some(OutputFormat::CodeClimate)),
            ("code_climate", Some(OutputFormat::CodeClimate)),
            ("gitlab", Some(OutputFormat::CodeClimate)),
            ("unknown", None),
        ];
        for (input, expected) in cases {
            assert_eq!(
                OutputFormat::from_str_loose(input),
                expected,
                "input: {input}"
            );
        }
    }

    #[test]
    fn test_create_formatter_all_formats() {
        for fmt in [
            OutputFormat::Json,
            OutputFormat::Markdown,
            OutputFormat::Terminal,
            OutputFormat::PrComment,
            OutputFormat::Annotations,
            OutputFormat::CodeClimate,
        ] {
            let formatter = create_formatter(fmt);
            let output = formatter.format_findings(&[]);
            assert!(!output.is_empty(), "format {fmt:?} should produce output");
        }
    }

    #[test]
    fn test_severity_icon() {
        assert_eq!(severity_icon(&Severity::Error), "[E]");
        assert_eq!(severity_icon(&Severity::Warning), "[W]");
        assert_eq!(severity_icon(&Severity::Info), "[I]");
    }
}
