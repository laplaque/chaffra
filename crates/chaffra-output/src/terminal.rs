//! Terminal output formatter with severity indicators.

use crate::{Formatter, severity_icon};
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use std::collections::BTreeMap;

/// Terminal formatter -- human-readable colored output grouped by file.
pub struct TerminalFormatter;

impl Formatter for TerminalFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let mut out = String::new();

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
            out.push_str(&format!("\n{file}\n"));
            for f in file_findings {
                let icon = severity_icon(&f.severity);
                out.push_str(&format!(
                    "  {icon} line {}: {} ({})\n",
                    f.location.start_line, f.message, f.rule_id
                ));
            }
        }

        // Summary line.
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

        out.push_str(&format!(
            "\n{} error(s), {} warning(s), {} info(s)\n",
            errors, warnings, infos
        ));

        out
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Project Health: {} ({})\n",
            health.score, health.grade
        ));
        out.push_str(&format!("Files analyzed: {}\n", health.total_files));

        if !health.files.is_empty() {
            out.push('\n');
            for f in &health.files {
                let indicator = match f.grade {
                    chaffra_core::diagnostic::HealthGrade::A => "+",
                    chaffra_core::diagnostic::HealthGrade::B => "+",
                    chaffra_core::diagnostic::HealthGrade::C => "~",
                    chaffra_core::diagnostic::HealthGrade::D => "-",
                    chaffra_core::diagnostic::HealthGrade::F => "!",
                };
                out.push_str(&format!(
                    "  [{indicator}] {} - {} ({})\n",
                    f.file, f.score, f.grade
                ));
            }
        }

        out
    }

    fn format_result(&self, result: &AnalysisResult, health: Option<&ProjectHealth>) -> String {
        let mut out = String::new();
        out.push_str("=== Chaffra Analysis ===\n\n");

        if let Some(h) = health {
            out.push_str(&self.format_health(h));
            out.push('\n');
        }

        out.push_str(&self.format_findings(&result.findings));

        out.push_str(&format!(
            "\nAnalyzed {} file(s) in {}ms\n",
            result.metrics.files_analyzed, result.metrics.duration_ms
        ));

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::*;
    use std::collections::HashMap;

    #[test]
    fn test_terminal_findings() {
        let formatter = TerminalFormatter;
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
        assert!(output.contains("test.go"));
        assert!(output.contains("[W]"));
        assert!(output.contains("line 5"));
    }

    #[test]
    fn test_terminal_health() {
        let formatter = TerminalFormatter;
        let health = ProjectHealth {
            score: 92,
            grade: HealthGrade::A,
            files: vec![FileHealthScore {
                file: "main.go".to_owned(),
                score: 92,
                grade: HealthGrade::A,
                cyclomatic_penalty: 0,
                cognitive_penalty: 0,
                size_penalty: 5,
                nesting_penalty: 3,
            }],
            total_files: 1,
        };
        let output = formatter.format_health(&health);
        assert!(output.contains("92"));
        assert!(output.contains("main.go"));
    }

    #[test]
    fn test_terminal_empty() {
        let formatter = TerminalFormatter;
        let output = formatter.format_findings(&[]);
        assert!(output.contains("No issues found"));
    }

    #[test]
    fn test_terminal_format_result_with_health() {
        let formatter = TerminalFormatter;
        let result = AnalysisResult {
            findings: vec![Finding {
                rule_id: "unused-import".to_owned(),
                message: "import os unused".to_owned(),
                severity: Severity::Warning,
                location: Location {
                    file: "app.py".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            }],
            metrics: ModuleMetrics {
                files_analyzed: 2,
                duration_ms: 15,
                counters: HashMap::new(),
                ..Default::default()
            },
        };
        let health = ProjectHealth {
            score: 55,
            grade: HealthGrade::F,
            files: vec![
                FileHealthScore {
                    file: "a.py".to_owned(),
                    score: 55,
                    grade: HealthGrade::F,
                    cyclomatic_penalty: 20,
                    cognitive_penalty: 15,
                    size_penalty: 5,
                    nesting_penalty: 5,
                },
                FileHealthScore {
                    file: "b.py".to_owned(),
                    score: 65,
                    grade: HealthGrade::D,
                    cyclomatic_penalty: 15,
                    cognitive_penalty: 10,
                    size_penalty: 5,
                    nesting_penalty: 5,
                },
                FileHealthScore {
                    file: "c.py".to_owned(),
                    score: 72,
                    grade: HealthGrade::C,
                    cyclomatic_penalty: 10,
                    cognitive_penalty: 8,
                    size_penalty: 5,
                    nesting_penalty: 5,
                },
            ],
            total_files: 3,
        };
        let output = formatter.format_result(&result, Some(&health));
        assert!(output.contains("=== Chaffra Analysis ==="));
        assert!(output.contains("55"));
        assert!(output.contains("[!]")); // F grade indicator
        assert!(output.contains("[-]")); // D grade indicator
        assert!(output.contains("[~]")); // C grade indicator
        assert!(output.contains("2 file(s) in 15ms"));
    }
}
