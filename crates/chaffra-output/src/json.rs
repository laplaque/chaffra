//! JSON output formatter.

use crate::Formatter;
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth};
use serde::Serialize;

/// JSON formatter -- produces typed, structured JSON output.
pub struct JsonFormatter;

#[derive(Serialize)]
struct JsonOutput<'a> {
    findings: &'a [Finding],
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<&'a ProjectHealth>,
    metrics: Option<&'a chaffra_core::diagnostic::ModuleMetrics>,
}

impl Formatter for JsonFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let output = JsonOutput {
            findings,
            health: None,
            metrics: None,
        };
        serde_json::to_string_pretty(&output).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        serde_json::to_string_pretty(health).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn format_result(&self, result: &AnalysisResult, health: Option<&ProjectHealth>) -> String {
        let output = JsonOutput {
            findings: &result.findings,
            health,
            metrics: Some(&result.metrics),
        };
        serde_json::to_string_pretty(&output).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::*;
    use std::collections::HashMap;

    #[test]
    fn test_json_findings() {
        let formatter = JsonFormatter;
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
        assert!(output.contains("unused-function"));
        assert!(output.contains("test.go"));
        // Should be valid JSON.
        let _: serde_json::Value = serde_json::from_str(&output).unwrap();
    }

    #[test]
    fn test_json_health() {
        let formatter = JsonFormatter;
        let health = ProjectHealth {
            score: 85,
            grade: HealthGrade::B,
            files: vec![],
            total_files: 5,
        };
        let output = formatter.format_health(&health);
        assert!(output.contains("85"));
        let _: serde_json::Value = serde_json::from_str(&output).unwrap();
    }

    #[test]
    fn test_json_result() {
        let formatter = JsonFormatter;
        let result = AnalysisResult {
            findings: vec![],
            metrics: ModuleMetrics {
                files_analyzed: 3,
                duration_ms: 100,
                counters: HashMap::new(),
            },
        };
        let output = formatter.format_result(&result, None);
        assert!(output.contains("findings"));
        let _: serde_json::Value = serde_json::from_str(&output).unwrap();
    }
}
