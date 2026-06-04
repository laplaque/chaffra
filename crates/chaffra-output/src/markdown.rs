//! Markdown output formatter.

use crate::{Formatter, severity_icon};
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use std::collections::BTreeMap;

/// Markdown formatter -- produces readable markdown with sections.
pub struct MarkdownFormatter;

impl Formatter for MarkdownFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let mut out = String::new();
        out.push_str("## Findings\n\n");

        if findings.is_empty() {
            out.push_str("No issues found.\n");
            return out;
        }

        // Group by file.
        let mut by_file: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
        for f in findings {
            by_file.entry(&f.location.file).or_default().push(f);
        }

        for (file, file_findings) in &by_file {
            out.push_str(&format!("### {file}\n\n"));
            for f in file_findings {
                out.push_str(&format!(
                    "- {} **{}** (line {}): {}\n",
                    severity_icon(&f.severity),
                    f.rule_id,
                    f.location.start_line,
                    f.message
                ));
            }
            out.push('\n');
        }

        out
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        let mut out = String::new();
        out.push_str("## Health Report\n\n");
        out.push_str(&format!(
            "**Project Score:** {} ({})\n\n",
            health.score, health.grade
        ));
        out.push_str(&format!("**Files Analyzed:** {}\n\n", health.total_files));

        if !health.files.is_empty() {
            out.push_str("| File | Score | Grade |\n");
            out.push_str("|------|-------|-------|\n");
            for f in &health.files {
                out.push_str(&format!("| {} | {} | {} |\n", f.file, f.score, f.grade));
            }
            out.push('\n');
        }

        out
    }

    fn format_result(&self, result: &AnalysisResult, health: Option<&ProjectHealth>) -> String {
        let mut out = String::new();
        out.push_str("# Chaffra Analysis Report\n\n");

        // Summary.
        out.push_str("## Summary\n\n");
        let errors = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();
        let warnings = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        let infos = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();

        out.push_str(&format!(
            "- **Errors:** {errors}\n- **Warnings:** {warnings}\n- **Info:** {infos}\n\n"
        ));

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

    #[test]
    fn test_markdown_findings() {
        let formatter = MarkdownFormatter;
        let findings = vec![Finding {
            rule_id: "unused-function".to_owned(),
            message: "function `foo` is never used".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 5,
                end_line: 10,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let output = formatter.format_findings(&findings);
        assert!(output.contains("## Findings"));
        assert!(output.contains("test.go"));
        assert!(output.contains("[W]"));
    }

    #[test]
    fn test_markdown_health() {
        let formatter = MarkdownFormatter;
        let health = ProjectHealth {
            score: 85,
            grade: HealthGrade::B,
            files: vec![FileHealthScore {
                file: "main.go".to_owned(),
                score: 85,
                grade: HealthGrade::B,
                cyclomatic_penalty: 5,
                cognitive_penalty: 5,
                size_penalty: 5,
                nesting_penalty: 0,
            }],
            total_files: 1,
        };
        let output = formatter.format_health(&health);
        assert!(output.contains("85"));
        assert!(output.contains("main.go"));
    }

    #[test]
    fn test_markdown_empty_findings() {
        let formatter = MarkdownFormatter;
        let output = formatter.format_findings(&[]);
        assert!(output.contains("No issues found"));
    }

    #[test]
    fn test_markdown_format_result_with_health() {
        let formatter = MarkdownFormatter;
        let result = AnalysisResult {
            findings: vec![
                Finding {
                    rule_id: "unused-function".to_owned(),
                    message: "f unused".to_owned(),
                    severity: Severity::Warning,
                    location: Location {
                        file: "a.go".to_owned(),
                        start_line: 1,
                        end_line: 2,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 1.0,
                    actions: vec![],
                    metadata: HashMap::new(),
                },
                Finding {
                    rule_id: "high-cyclomatic".to_owned(),
                    message: "too complex".to_owned(),
                    severity: Severity::Error,
                    location: Location {
                        file: "b.go".to_owned(),
                        start_line: 10,
                        end_line: 20,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.9,
                    actions: vec![],
                    metadata: HashMap::new(),
                },
                Finding {
                    rule_id: "note".to_owned(),
                    message: "info note".to_owned(),
                    severity: Severity::Info,
                    location: Location {
                        file: "c.go".to_owned(),
                        start_line: 1,
                        end_line: 1,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 1.0,
                    actions: vec![],
                    metadata: HashMap::new(),
                },
            ],
            metrics: ModuleMetrics {
                files_analyzed: 3,
                duration_ms: 42,
                counters: HashMap::new(),
            },
        };
        let health = ProjectHealth {
            score: 75,
            grade: HealthGrade::C,
            files: vec![],
            total_files: 3,
        };
        let output = formatter.format_result(&result, Some(&health));
        assert!(output.contains("# Chaffra Analysis Report"));
        assert!(output.contains("Errors:** 1"));
        assert!(output.contains("Warnings:** 1"));
        assert!(output.contains("Info:** 1"));
        assert!(output.contains("75"));
    }
}
