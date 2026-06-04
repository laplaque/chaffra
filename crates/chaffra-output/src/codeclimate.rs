//! CodeClimate JSON output formatter.
//!
//! Produces CodeClimate-compatible JSON used by GitLab CI and other tools
//! to render code quality reports inline.

use crate::Formatter;
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use serde::Serialize;

/// CodeClimate formatter.
pub struct CodeClimateFormatter;

/// A single issue in CodeClimate format.
#[derive(Debug, Serialize)]
struct CodeClimateIssue {
    #[serde(rename = "type")]
    issue_type: String,
    check_name: String,
    description: String,
    severity: String,
    fingerprint: String,
    location: CodeClimateLocation,
    categories: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CodeClimateLocation {
    path: String,
    lines: CodeClimateLines,
}

#[derive(Debug, Serialize)]
struct CodeClimateLines {
    begin: u32,
    end: u32,
}

fn severity_to_codeclimate(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "critical",
        Severity::Warning => "major",
        Severity::Info => "minor",
    }
}

fn compute_fingerprint(finding: &Finding) -> String {
    // Simple deterministic fingerprint from rule + file + line.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    finding.rule_id.hash(&mut hasher);
    finding.location.file.hash(&mut hasher);
    finding.location.start_line.hash(&mut hasher);
    finding.message.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn findings_to_codeclimate(findings: &[Finding]) -> Vec<CodeClimateIssue> {
    findings
        .iter()
        .map(|f| CodeClimateIssue {
            issue_type: "issue".to_owned(),
            check_name: f.rule_id.clone(),
            description: f.message.clone(),
            severity: severity_to_codeclimate(&f.severity).to_owned(),
            fingerprint: compute_fingerprint(f),
            location: CodeClimateLocation {
                path: f.location.file.clone(),
                lines: CodeClimateLines {
                    begin: f.location.start_line,
                    end: f.location.end_line,
                },
            },
            categories: vec!["Bug Risk".to_owned()],
        })
        .collect()
}

impl Formatter for CodeClimateFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let issues = findings_to_codeclimate(findings);
        serde_json::to_string_pretty(&issues)
            .unwrap_or_else(|e| format!("[{{\"error\": \"{e}\"}}]"))
    }

    fn format_health(&self, _health: &ProjectHealth) -> String {
        // CodeClimate format does not have a direct health equivalent.
        "[]".to_owned()
    }

    fn format_result(&self, result: &AnalysisResult, _health: Option<&ProjectHealth>) -> String {
        self.format_findings(&result.findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::*;
    use std::collections::HashMap;

    fn make_finding(rule_id: &str, file: &str, line: u32) -> Finding {
        Finding {
            rule_id: rule_id.to_owned(),
            message: format!("{rule_id} detected"),
            severity: Severity::Warning,
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
    fn test_codeclimate_empty() {
        let f = CodeClimateFormatter;
        let output = f.format_findings(&[]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_codeclimate_single_finding() {
        let f = CodeClimateFormatter;
        let findings = vec![make_finding("unused-function", "main.go", 5)];
        let output = f.format_findings(&findings);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["check_name"], "unused-function");
        assert_eq!(parsed[0]["severity"], "major");
        assert_eq!(parsed[0]["location"]["path"], "main.go");
        assert_eq!(parsed[0]["location"]["lines"]["begin"], 5);
    }

    #[test]
    fn test_codeclimate_severity_mapping() {
        assert_eq!(severity_to_codeclimate(&Severity::Error), "critical");
        assert_eq!(severity_to_codeclimate(&Severity::Warning), "major");
        assert_eq!(severity_to_codeclimate(&Severity::Info), "minor");
    }

    #[test]
    fn test_codeclimate_fingerprint_deterministic() {
        let f1 = make_finding("rule", "file.go", 10);
        let f2 = make_finding("rule", "file.go", 10);
        assert_eq!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn test_codeclimate_fingerprint_differs() {
        let f1 = make_finding("rule-a", "file.go", 10);
        let f2 = make_finding("rule-b", "file.go", 10);
        assert_ne!(compute_fingerprint(&f1), compute_fingerprint(&f2));
    }

    #[test]
    fn test_codeclimate_health_returns_empty_array() {
        let f = CodeClimateFormatter;
        let health = ProjectHealth {
            score: 90,
            grade: HealthGrade::A,
            files: vec![],
            total_files: 1,
        };
        assert_eq!(f.format_health(&health), "[]");
    }

    #[test]
    fn test_codeclimate_multiple_findings() {
        let f = CodeClimateFormatter;
        let findings = vec![
            make_finding("unused-function", "a.go", 1),
            make_finding("high-cyclomatic", "b.go", 10),
        ];
        let output = f.format_findings(&findings);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
