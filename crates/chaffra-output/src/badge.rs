//! Badge output formatter -- shields.io-compatible JSON.

use crate::Formatter;
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use serde::Serialize;

/// Shields.io endpoint badge JSON.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BadgeJson {
    schema_version: u32,
    label: String,
    message: String,
    color: String,
}

/// Badge formatter -- produces shields.io-compatible JSON.
pub struct BadgeFormatter;

/// Determine badge color from a health score.
///
/// - green: score >= 80
/// - yellow: score >= 60
/// - red: score < 60
fn badge_color(score: u32) -> &'static str {
    if score >= 80 {
        "green"
    } else if score >= 60 {
        "yellow"
    } else {
        "red"
    }
}

impl Formatter for BadgeFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let total = findings.len();
        let errors = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count();

        let (message, color) = if errors > 0 {
            (format!("{errors} error(s)"), "red")
        } else if total > 0 {
            (format!("{total} finding(s)"), "yellow")
        } else {
            ("clean".to_owned(), "green")
        };

        let badge = BadgeJson {
            schema_version: 1,
            label: "chaffra".to_owned(),
            message,
            color: color.to_owned(),
        };
        serde_json::to_string_pretty(&badge).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        let badge = BadgeJson {
            schema_version: 1,
            label: "chaffra health".to_owned(),
            message: format!("{}%", health.score),
            color: badge_color(health.score).to_owned(),
        };
        serde_json::to_string_pretty(&badge).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn format_result(&self, result: &AnalysisResult, health: Option<&ProjectHealth>) -> String {
        if let Some(h) = health {
            self.format_health(h)
        } else {
            self.format_findings(&result.findings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::*;
    use std::collections::HashMap;

    #[test]
    fn test_badge_color_green() {
        assert_eq!(badge_color(80), "green");
        assert_eq!(badge_color(90), "green");
        assert_eq!(badge_color(100), "green");
    }

    #[test]
    fn test_badge_color_yellow() {
        assert_eq!(badge_color(60), "yellow");
        assert_eq!(badge_color(70), "yellow");
        assert_eq!(badge_color(79), "yellow");
    }

    #[test]
    fn test_badge_color_red() {
        assert_eq!(badge_color(0), "red");
        assert_eq!(badge_color(50), "red");
        assert_eq!(badge_color(59), "red");
    }

    #[test]
    fn test_badge_health() {
        let formatter = BadgeFormatter;
        let health = ProjectHealth {
            score: 85,
            grade: HealthGrade::B,
            files: vec![],
            total_files: 5,
        };
        let output = formatter.format_health(&health);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["schemaVersion"], 1);
        assert_eq!(parsed["label"], "chaffra health");
        assert_eq!(parsed["message"], "85%");
        assert_eq!(parsed["color"], "green");
    }

    #[test]
    fn test_badge_health_low_score() {
        let formatter = BadgeFormatter;
        let health = ProjectHealth {
            score: 45,
            grade: HealthGrade::F,
            files: vec![],
            total_files: 3,
        };
        let output = formatter.format_health(&health);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["color"], "red");
        assert_eq!(parsed["message"], "45%");
    }

    #[test]
    fn test_badge_findings_clean() {
        let formatter = BadgeFormatter;
        let output = formatter.format_findings(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["message"], "clean");
        assert_eq!(parsed["color"], "green");
    }

    #[test]
    fn test_badge_findings_with_errors() {
        let formatter = BadgeFormatter;
        let findings = vec![Finding {
            rule_id: "test".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Error,
            location: Location {
                file: "t.go".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let output = formatter.format_findings(&findings);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["color"], "red");
        assert!(parsed["message"].as_str().unwrap().contains("error"));
    }

    #[test]
    fn test_badge_findings_warnings_only() {
        let formatter = BadgeFormatter;
        let findings = vec![Finding {
            rule_id: "test".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "t.go".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let output = formatter.format_findings(&findings);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["color"], "yellow");
        assert!(parsed["message"].as_str().unwrap().contains("finding"));
    }

    #[test]
    fn test_badge_result_with_health() {
        let formatter = BadgeFormatter;
        let result = AnalysisResult {
            findings: vec![],
            metrics: ModuleMetrics {
                files_analyzed: 1,
                duration_ms: 10,
                counters: HashMap::new(),
            },
        };
        let health = ProjectHealth {
            score: 70,
            grade: HealthGrade::C,
            files: vec![],
            total_files: 1,
        };
        let output = formatter.format_result(&result, Some(&health));
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["color"], "yellow");
        assert_eq!(parsed["message"], "70%");
    }

    #[test]
    fn test_badge_result_without_health() {
        let formatter = BadgeFormatter;
        let result = AnalysisResult {
            findings: vec![],
            metrics: ModuleMetrics {
                files_analyzed: 1,
                duration_ms: 10,
                counters: HashMap::new(),
            },
        };
        let output = formatter.format_result(&result, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["message"], "clean");
    }
}
