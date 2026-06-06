//! SARIF 2.1.0 output formatter.
//!
//! Maps chaffra findings to the SARIF (Static Analysis Results Interchange Format)
//! schema version 2.1.0. Each finding becomes a SARIF `result`, and each unique
//! rule becomes a `reportingDescriptor` in the tool's `rules` array.

use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth, Severity};
use serde::Serialize;
use std::collections::HashMap;

use crate::Formatter;

/// SARIF 2.1.0 formatter.
pub struct SarifFormatter;

impl Formatter for SarifFormatter {
    fn format_findings(&self, findings: &[Finding]) -> String {
        let sarif = build_sarif(findings);
        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_owned())
    }

    fn format_health(&self, _health: &ProjectHealth) -> String {
        // SARIF is designed for findings, not health scores.
        // Return an empty SARIF log.
        let sarif = build_sarif(&[]);
        serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_owned())
    }

    fn format_result(&self, result: &AnalysisResult, _health: Option<&ProjectHealth>) -> String {
        self.format_findings(&result.findings)
    }
}

/// Build a complete SARIF 2.1.0 JSON structure.
fn build_sarif(findings: &[Finding]) -> SarifLog {
    // Collect unique rules.
    let mut rule_map: HashMap<String, ReportingDescriptor> = HashMap::new();
    let mut rule_order: Vec<String> = Vec::new();

    for finding in findings {
        if !rule_map.contains_key(&finding.rule_id) {
            rule_order.push(finding.rule_id.clone());
            rule_map.insert(
                finding.rule_id.clone(),
                ReportingDescriptor {
                    id: finding.rule_id.clone(),
                    short_description: MultiformatMessage {
                        text: finding.rule_id.clone(),
                    },
                    default_configuration: DefaultConfiguration {
                        level: severity_to_sarif_level(&finding.severity),
                    },
                    properties: RuleProperties { tags: vec![] },
                },
            );
        }
    }

    let rules: Vec<ReportingDescriptor> = rule_order
        .iter()
        .filter_map(|id| rule_map.remove(id))
        .collect();

    // Build rule index map for results.
    let rule_index: HashMap<String, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.clone(), i))
        .collect();

    // Convert findings to SARIF results.
    let results: Vec<SarifResult> = findings
        .iter()
        .map(|f| {
            let idx = rule_index.get(&f.rule_id).copied().unwrap_or(0);
            SarifResult {
                rule_id: f.rule_id.clone(),
                rule_index: idx,
                level: severity_to_sarif_level(&f.severity),
                message: Message {
                    text: f.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation {
                            uri: f.location.file.clone(),
                            uri_base_id: "%SRCROOT%".to_owned(),
                        },
                        region: Region {
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
                properties: ResultProperties {
                    confidence: f.confidence,
                    metadata: if f.metadata.is_empty() {
                        None
                    } else {
                        Some(f.metadata.clone())
                    },
                },
            }
        })
        .collect();

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_owned(),
        version: "2.1.0".to_owned(),
        runs: vec![Run {
            tool: Tool {
                driver: ToolComponent {
                    name: "chaffra".to_owned(),
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                    semantic_version: env!("CARGO_PKG_VERSION").to_owned(),
                    information_uri: "https://github.com/laplaque/chaffra".to_owned(),
                    rules,
                },
            },
            results,
        }],
    }
}

/// Map chaffra severity to SARIF level string.
fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::Error => "error".to_owned(),
        Severity::Warning => "warning".to_owned(),
        Severity::Info => "note".to_owned(),
    }
}

// ---- SARIF data structures ----

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: String,
    version: String,
    runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Run {
    tool: Tool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Tool {
    driver: ToolComponent,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolComponent {
    name: String,
    version: String,
    semantic_version: String,
    information_uri: String,
    rules: Vec<ReportingDescriptor>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReportingDescriptor {
    id: String,
    short_description: MultiformatMessage,
    default_configuration: DefaultConfiguration,
    properties: RuleProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MultiformatMessage {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DefaultConfiguration {
    level: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuleProperties {
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    rule_index: usize,
    level: String,
    message: Message,
    locations: Vec<SarifLocation>,
    properties: ResultProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Message {
    text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    region: Region,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
    uri_base_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u32,
    end_line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultProperties {
    confidence: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::Location;
    use serde_json::Value;

    #[test]
    fn test_empty_findings() {
        let formatter = SarifFormatter;
        let output = formatter.format_findings(&[]);
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(
            parsed["$schema"]
                .as_str()
                .unwrap()
                .contains("sarif-schema-2.1.0")
        );
        assert!(parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_single_finding() {
        let formatter = SarifFormatter;
        let findings = vec![Finding {
            rule_id: "unused-function".to_owned(),
            message: "Function `helper` is never used".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "src/lib.go".to_owned(),
                start_line: 10,
                end_line: 20,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.95,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let output = formatter.format_findings(&findings);
        let parsed: Value = serde_json::from_str(&output).unwrap();

        // Check structure.
        assert_eq!(parsed["version"], "2.1.0");
        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "unused-function");
        assert_eq!(results[0]["level"], "warning");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/lib.go"
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            10
        );

        // Check rules.
        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "unused-function");
    }

    #[test]
    fn test_multiple_rules() {
        let formatter = SarifFormatter;
        let findings = vec![
            Finding {
                rule_id: "unused-function".to_owned(),
                message: "unused func".to_owned(),
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
                rule_id: "boundary-violation".to_owned(),
                message: "bad import".to_owned(),
                severity: Severity::Error,
                location: Location {
                    file: "b.go".to_owned(),
                    start_line: 5,
                    end_line: 5,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            },
        ];
        let output = formatter.format_findings(&findings);
        let parsed: Value = serde_json::from_str(&output).unwrap();

        let rules = parsed["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 2);

        let results = parsed["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[1]["level"], "error");
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Error), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Warning), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn test_sarif_valid_json() {
        let formatter = SarifFormatter;
        let findings = vec![Finding {
            rule_id: "test-rule".to_owned(),
            message: "test message".to_owned(),
            severity: Severity::Info,
            location: Location {
                file: "test.py".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 5,
                end_column: 10,
            },
            confidence: 0.8,
            actions: vec![],
            metadata: {
                let mut m = HashMap::new();
                m.insert("key".to_owned(), "value".to_owned());
                m
            },
        }];
        let output = formatter.format_findings(&findings);

        // Verify it parses as valid JSON.
        let parsed: Value = serde_json::from_str(&output).unwrap();

        // Check columns are present for non-zero values.
        let region = &parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startColumn"], 5);
        assert_eq!(region["endColumn"], 10);

        // Check metadata is present.
        assert_eq!(
            parsed["runs"][0]["results"][0]["properties"]["metadata"]["key"],
            "value"
        );
    }

    #[test]
    fn test_sarif_schema_url() {
        let sarif = build_sarif(&[]);
        assert!(sarif.schema.contains("sarif-schema-2.1.0"));
        assert_eq!(sarif.version, "2.1.0");
    }

    #[test]
    fn test_rule_index_consistency() {
        let findings = vec![
            Finding {
                rule_id: "rule-a".to_owned(),
                message: "a".to_owned(),
                severity: Severity::Warning,
                location: Location {
                    file: "a.go".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            },
            Finding {
                rule_id: "rule-b".to_owned(),
                message: "b".to_owned(),
                severity: Severity::Error,
                location: Location {
                    file: "b.go".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            },
            Finding {
                rule_id: "rule-a".to_owned(),
                message: "a again".to_owned(),
                severity: Severity::Warning,
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
        ];
        let sarif = build_sarif(&findings);
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), 2);
        // First result should reference rule index 0 (rule-a).
        assert_eq!(sarif.runs[0].results[0].rule_index, 0);
        // Second result should reference rule index 1 (rule-b).
        assert_eq!(sarif.runs[0].results[1].rule_index, 1);
        // Third result should reference rule index 0 (rule-a again).
        assert_eq!(sarif.runs[0].results[2].rule_index, 0);
    }
}
