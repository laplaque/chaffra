//! GitHub PR comment formatter.
//!
//! Produces markdown optimized for GitHub pull request comments with collapsible
//! sections, severity badges, and a summary table.

use crate::{Formatter, severity_icon};
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use std::collections::BTreeMap;

/// PR comment formatter -- produces GitHub-flavored markdown for PR comments.
pub struct PrCommentFormatter;

impl Formatter for PrCommentFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let mut out = String::new();

        if findings.is_empty() {
            out.push_str("### Chaffra: No issues found\n\n");
            out.push_str("All checks passed.\n");
            return out;
        }

        let errors = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warnings = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        let infos = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        out.push_str("### Chaffra Analysis\n\n");
        out.push_str(&format!(
            "| Errors | Warnings | Info |\n|--------|----------|------|\n| {errors} | {warnings} | {infos} |\n\n"
        ));

        // Group by file.
        let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            by_file.entry(&f.location.file).or_default().push(f);
        }

        for (file, file_findings) in &by_file {
            out.push_str(&format!(
                "<details>\n<summary><b>{file}</b> ({} issue{})</summary>\n\n",
                file_findings.len(),
                if file_findings.len() == 1 { "" } else { "s" }
            ));
            for f in file_findings {
                out.push_str(&format!(
                    "- {} **{}** (line {}): {}\n",
                    severity_icon(&f.severity),
                    f.rule_id,
                    f.location.start_line,
                    f.message
                ));
            }
            out.push_str("\n</details>\n\n");
        }

        out
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "### Health: {} ({})\n\n",
            health.score, health.grade
        ));
        out.push_str(&format!("Files analyzed: {}\n", health.total_files));
        out
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
            message: format!("{rule_id} at line {line}"),
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
    fn test_pr_comment_empty() {
        let f = PrCommentFormatter;
        let output = f.format_findings(&[]);
        assert!(output.contains("No issues found"));
        assert!(output.contains("All checks passed"));
    }

    #[test]
    fn test_pr_comment_with_findings() {
        let f = PrCommentFormatter;
        let findings = vec![
            make_finding("unused-function", "main.go", 5, Severity::Warning),
            make_finding("high-cyclomatic", "main.go", 10, Severity::Error),
            make_finding("note", "utils.go", 1, Severity::Info),
        ];
        let output = f.format_findings(&findings);
        assert!(output.contains("### Chaffra Analysis"));
        assert!(output.contains("| 1 | 1 | 1 |"));
        assert!(output.contains("<details>"));
        assert!(output.contains("main.go"));
        assert!(output.contains("utils.go"));
    }

    #[test]
    fn test_pr_comment_health() {
        let f = PrCommentFormatter;
        let health = ProjectHealth {
            score: 85,
            grade: HealthGrade::B,
            files: vec![],
            total_files: 3,
        };
        let output = f.format_health(&health);
        assert!(output.contains("85"));
        assert!(output.contains("B"));
    }

    #[test]
    fn test_pr_comment_result_with_health() {
        let f = PrCommentFormatter;
        let result = AnalysisResult {
            findings: vec![make_finding("issue", "a.go", 1, Severity::Warning)],
            metrics: ModuleMetrics {
                files_analyzed: 1,
                duration_ms: 10,
                counters: HashMap::new(),
            },
        };
        let health = ProjectHealth {
            score: 90,
            grade: HealthGrade::A,
            files: vec![],
            total_files: 1,
        };
        let output = f.format_result(&result, Some(&health));
        assert!(output.contains("Health: 90"));
        assert!(output.contains("Chaffra Analysis"));
    }
}
