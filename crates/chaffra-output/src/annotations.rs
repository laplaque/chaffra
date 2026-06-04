//! GitHub Actions annotations formatter.
//!
//! Produces `::error file=...` and `::warning file=...` annotations that GitHub
//! Actions renders inline on the diff view.

use crate::Formatter;
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};

/// Annotations formatter -- produces GitHub Actions workflow commands.
pub struct AnnotationsFormatter;

impl Formatter for AnnotationsFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        if findings.is_empty() {
            return "::notice::Chaffra: no issues found\n".to_owned();
        }

        let mut out = String::new();
        for f in findings {
            let level = match f.severity {
                Severity::Error => "error",
                Severity::Warning => "warning",
                Severity::Info => "notice",
            };
            // GitHub Actions annotation format:
            // ::error file={name},line={line},col={col}::{message}
            out.push_str(&format!(
                "::{level} file={},line={},col={}::{} ({})\n",
                f.location.file,
                f.location.start_line,
                f.location.start_column,
                f.message,
                f.rule_id,
            ));
        }
        out
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        let level = if health.score >= 80 {
            "notice"
        } else {
            "warning"
        };
        format!(
            "::{level}::Chaffra health: {} ({}) - {} files\n",
            health.score, health.grade, health.total_files
        )
    }

    fn format_result(&self, result: &AnalysisResult, health: Option<&ProjectHealth>) -> String {
        let mut out = String::new();
        if let Some(h) = health {
            out.push_str(&self.format_health(h));
        }
        out.push_str(&self.format_findings(&result.findings));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::*;
    use std::collections::HashMap;

    fn make_finding(rule_id: &str, file: &str, line: u32, severity: Severity) -> Finding {
        Finding {
            rule_id: rule_id.to_owned(),
            message: format!("{rule_id} detected"),
            severity,
            location: Location {
                file: file.to_owned(),
                start_line: line,
                end_line: line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_annotations_empty() {
        let f = AnnotationsFormatter;
        let output = f.format_findings(&[]);
        assert!(output.contains("::notice::"));
        assert!(output.contains("no issues found"));
    }

    #[test]
    fn test_annotations_error() {
        let f = AnnotationsFormatter;
        let findings = vec![make_finding(
            "high-cyclomatic",
            "main.go",
            5,
            Severity::Error,
        )];
        let output = f.format_findings(&findings);
        assert!(output.starts_with("::error file=main.go,line=5,col=0::"));
        assert!(output.contains("high-cyclomatic"));
    }

    #[test]
    fn test_annotations_warning() {
        let f = AnnotationsFormatter;
        let findings = vec![make_finding(
            "unused-function",
            "a.go",
            3,
            Severity::Warning,
        )];
        let output = f.format_findings(&findings);
        assert!(output.starts_with("::warning file=a.go"));
    }

    #[test]
    fn test_annotations_info() {
        let f = AnnotationsFormatter;
        let findings = vec![make_finding("note", "b.go", 1, Severity::Info)];
        let output = f.format_findings(&findings);
        assert!(output.starts_with("::notice file=b.go"));
    }

    #[test]
    fn test_annotations_health_good() {
        let f = AnnotationsFormatter;
        let health = ProjectHealth {
            score: 90,
            grade: HealthGrade::A,
            files: vec![],
            total_files: 5,
        };
        let output = f.format_health(&health);
        assert!(output.starts_with("::notice::"));
        assert!(output.contains("90"));
    }

    #[test]
    fn test_annotations_health_warning() {
        let f = AnnotationsFormatter;
        let health = ProjectHealth {
            score: 65,
            grade: HealthGrade::D,
            files: vec![],
            total_files: 5,
        };
        let output = f.format_health(&health);
        assert!(output.starts_with("::warning::"));
    }

    #[test]
    fn test_annotations_result() {
        let f = AnnotationsFormatter;
        let result = AnalysisResult {
            findings: vec![make_finding("issue", "a.go", 1, Severity::Warning)],
            metrics: ModuleMetrics {
                files_analyzed: 1,
                duration_ms: 10,
                counters: HashMap::new(),
            },
        };
        let output = f.format_result(&result, None);
        assert!(output.contains("::warning file=a.go"));
    }
}
