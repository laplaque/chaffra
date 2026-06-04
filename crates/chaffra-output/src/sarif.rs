//! SARIF 2.1.0 output formatter.
//!
//! Maps chaffra findings to the Static Analysis Results Interchange Format
//! for integration with GitHub Code Scanning, VS Code, and other SARIF consumers.

use crate::Formatter;
use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use serde::Serialize;

/// SARIF 2.1.0 formatter.
pub struct SarifFormatter;

/// Top-level SARIF log.
#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    artifacts: Vec<SarifArtifact>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: String,
    version: String,
    #[serde(rename = "informationUri")]
    information_uri: String,
    rules: Vec<SarifReportingDescriptor>,
}

#[derive(Serialize)]
struct SarifReportingDescriptor {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: SarifConfiguration,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: String,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    message: SarifMessage,
    level: String,
    locations: Vec<SarifLocation>,
    #[serde(
        rename = "partialFingerprints",
        skip_serializing_if = "std::collections::HashMap::is_empty"
    )]
    partial_fingerprints: std::collections::HashMap<String, String>,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "endLine")]
    end_line: u32,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
}

#[derive(Serialize)]
struct SarifArtifact {
    location: SarifArtifactLocation,
}

fn severity_to_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

fn findings_to_sarif(findings: &[Finding]) -> SarifLog {
    // Collect unique rules.
    let mut rule_ids: Vec<String> = Vec::new();
    for f in findings {
        if !rule_ids.contains(&f.rule_id) {
            rule_ids.push(f.rule_id.clone());
        }
    }

    let rules: Vec<SarifReportingDescriptor> = rule_ids
        .iter()
        .map(|id| SarifReportingDescriptor {
            id: id.clone(),
            short_description: SarifMessage {
                text: id.replace('-', " "),
            },
            default_configuration: SarifConfiguration {
                level: "warning".to_owned(),
            },
        })
        .collect();

    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let mut partial_fingerprints = std::collections::HashMap::new();
            if let Some(family_id) = f.metadata.get("family_id") {
                partial_fingerprints.insert("familyId".to_owned(), family_id.clone());
            }

            SarifResult {
                rule_id: f.rule_id.clone(),
                message: SarifMessage {
                    text: f.message.clone(),
                },
                level: severity_to_level(&f.severity).to_owned(),
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: f.location.file.clone(),
                        },
                        region: SarifRegion {
                            start_line: f.location.start_line,
                            end_line: f.location.end_line,
                            start_column: if f.location.start_column > 0 {
                                Some(f.location.start_column)
                            } else {
                                None
                            },
                            end_column: if f.location.end_column > 0 {
                                Some(f.location.end_column)
                            } else {
                                None
                            },
                        },
                    },
                }],
                partial_fingerprints,
            }
        })
        .collect();

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_owned(),
        version: "2.1.0".to_owned(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "chaffra".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    information_uri: "https://github.com/laplaque/chaffra".to_owned(),
                    rules,
                },
            },
            results,
            artifacts: Vec::new(),
        }],
    }
}

impl Formatter for SarifFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let log = findings_to_sarif(findings);
        serde_json::to_string_pretty(&log).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }

    fn format_health(&self, health: &ProjectHealth) -> String {
        // SARIF does not have a native health format; emit as a single note.
        let finding = Finding {
            rule_id: "health-score".to_owned(),
            message: format!(
                "Project health score: {} (grade {})",
                health.score, health.grade
            ),
            severity: Severity::Info,
            location: chaffra_core::diagnostic::Location {
                file: ".".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: std::collections::HashMap::new(),
        };
        self.format_findings(&[finding])
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

    fn sample_finding() -> Finding {
        Finding {
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
        }
    }

    #[test]
    fn test_sarif_findings_valid_json() {
        let formatter = SarifFormatter;
        let output = formatter.format_findings(&[sample_finding()]);
        let parsed: serde_json::Value = serde_json::from_str(&output)
            .unwrap_or_else(|e| panic!("invalid SARIF JSON: {e}\n{output}"));
        assert_eq!(parsed["version"], "2.1.0");
        assert!(parsed["$schema"].as_str().unwrap().contains("sarif"));
    }

    #[test]
    fn test_sarif_contains_results() {
        let formatter = SarifFormatter;
        let output = formatter.format_findings(&[sample_finding()]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let results = &parsed["runs"][0]["results"];
        assert_eq!(results.as_array().unwrap().len(), 1);
        assert_eq!(results[0]["ruleId"], "unused-function");
        assert_eq!(results[0]["level"], "warning");
    }

    #[test]
    fn test_sarif_contains_rules() {
        let formatter = SarifFormatter;
        let output = formatter.format_findings(&[sample_finding()]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let rules = &parsed["runs"][0]["tool"]["driver"]["rules"];
        assert_eq!(rules.as_array().unwrap().len(), 1);
        assert_eq!(rules[0]["id"], "unused-function");
    }

    #[test]
    fn test_sarif_location() {
        let formatter = SarifFormatter;
        let output = formatter.format_findings(&[sample_finding()]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let loc = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "test.go");
        assert_eq!(loc["region"]["startLine"], 5);
        assert_eq!(loc["region"]["endLine"], 10);
    }

    #[test]
    fn test_sarif_empty_findings() {
        let formatter = SarifFormatter;
        let output = formatter.format_findings(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_sarif_health() {
        let formatter = SarifFormatter;
        let health = ProjectHealth {
            score: 85,
            grade: HealthGrade::B,
            files: vec![],
            total_files: 5,
        };
        let output = formatter.format_health(&health);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
    }

    #[test]
    fn test_sarif_result() {
        let formatter = SarifFormatter;
        let result = AnalysisResult {
            findings: vec![sample_finding()],
            metrics: ModuleMetrics {
                files_analyzed: 1,
                duration_ms: 50,
                counters: HashMap::new(),
            },
        };
        let output = formatter.format_result(&result, None);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_severity_to_level() {
        assert_eq!(severity_to_level(&Severity::Error), "error");
        assert_eq!(severity_to_level(&Severity::Warning), "warning");
        assert_eq!(severity_to_level(&Severity::Info), "note");
    }

    #[test]
    fn test_sarif_error_severity() {
        let formatter = SarifFormatter;
        let mut f = sample_finding();
        f.severity = Severity::Error;
        let output = formatter.format_findings(&[f]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn test_sarif_info_severity() {
        let formatter = SarifFormatter;
        let mut f = sample_finding();
        f.severity = Severity::Info;
        let output = formatter.format_findings(&[f]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["runs"][0]["results"][0]["level"], "note");
    }

    #[test]
    fn test_sarif_partial_fingerprints() {
        let formatter = SarifFormatter;
        let mut f = sample_finding();
        f.metadata
            .insert("family_id".to_owned(), "dup:12345678".to_owned());
        let output = formatter.format_findings(&[f]);
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            parsed["runs"][0]["results"][0]["partialFingerprints"]["familyId"],
            "dup:12345678"
        );
    }
}
