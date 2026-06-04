//! Protobuf message types for the AnalysisModule gRPC service.
//!
//! These types mirror the definitions in `proto/chaffra/module/v1/module.proto`
//! and are used for wire serialization in gRPC calls to external modules.

use std::collections::HashMap;

/// Empty request for `Describe` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct DescribeRequest {}

/// Module metadata returned by `Describe`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ModuleInfoProto {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub version: String,
    #[prost(string, repeated, tag = "4")]
    pub languages: Vec<String>,
    #[prost(string, repeated, tag = "5")]
    pub capabilities: Vec<String>,
    #[prost(message, repeated, tag = "6")]
    pub rules: Vec<RuleInfoProto>,
}

/// Rule metadata within a module.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RuleInfoProto {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub description: String,
    #[prost(string, tag = "4")]
    pub default_severity: String,
    #[prost(string, tag = "5")]
    pub category: String,
}

/// Request for `Analyze` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct AnalysisRequest {
    #[prost(message, repeated, tag = "1")]
    pub files: Vec<FileInfoProto>,
    #[prost(map = "string, string", tag = "2")]
    pub config: HashMap<String, String>,
    #[prost(string, repeated, tag = "3")]
    pub enabled_rules: Vec<String>,
    #[prost(string, tag = "4")]
    pub language: String,
}

/// File data sent to external modules.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FileInfoProto {
    #[prost(string, tag = "1")]
    pub path: String,
    #[prost(bytes = "vec", tag = "2")]
    pub content: Vec<u8>,
}

/// Response from `Analyze` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct AnalysisResponse {
    #[prost(message, repeated, tag = "1")]
    pub findings: Vec<FindingProto>,
    #[prost(message, optional, tag = "2")]
    pub metrics: Option<ModuleMetricsProto>,
}

/// A single finding from analysis.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FindingProto {
    #[prost(string, tag = "1")]
    pub rule_id: String,
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(string, tag = "3")]
    pub severity: String,
    #[prost(message, optional, tag = "4")]
    pub location: Option<LocationProto>,
    #[prost(float, tag = "5")]
    pub confidence: f32,
    #[prost(message, repeated, tag = "6")]
    pub actions: Vec<ActionProto>,
    #[prost(map = "string, string", tag = "7")]
    pub metadata: HashMap<String, String>,
}

/// Source location within a file.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LocationProto {
    #[prost(string, tag = "1")]
    pub file: String,
    #[prost(uint32, tag = "2")]
    pub start_line: u32,
    #[prost(uint32, tag = "3")]
    pub end_line: u32,
    #[prost(uint32, tag = "4")]
    pub start_column: u32,
    #[prost(uint32, tag = "5")]
    pub end_column: u32,
}

/// An available fix action.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ActionProto {
    #[prost(string, tag = "1")]
    pub description: String,
    #[prost(bool, tag = "2")]
    pub auto_fixable: bool,
    #[prost(message, repeated, tag = "3")]
    pub edits: Vec<TextEditProto>,
}

/// A text replacement edit.
#[derive(Clone, PartialEq, prost::Message)]
pub struct TextEditProto {
    #[prost(string, tag = "1")]
    pub file: String,
    #[prost(uint32, tag = "2")]
    pub start_line: u32,
    #[prost(uint32, tag = "3")]
    pub end_line: u32,
    #[prost(string, tag = "4")]
    pub new_text: String,
}

/// Aggregate metrics from an analysis run.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ModuleMetricsProto {
    #[prost(uint64, tag = "1")]
    pub files_analyzed: u64,
    #[prost(uint64, tag = "2")]
    pub duration_ms: u64,
    #[prost(map = "string, uint64", tag = "3")]
    pub counters: HashMap<String, u64>,
}

/// Request for `Explain` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ExplainRequest {
    #[prost(string, tag = "1")]
    pub rule_id: String,
}

/// Response from `Explain` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ExplainResponse {
    #[prost(string, tag = "1")]
    pub rule_id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub description: String,
    #[prost(string, tag = "4")]
    pub rationale: String,
    #[prost(string, tag = "5")]
    pub default_severity: String,
    #[prost(string, tag = "6")]
    pub suppression_syntax: String,
    #[prost(string, repeated, tag = "7")]
    pub examples: Vec<String>,
}

/// Request for `Fix` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FixRequest {
    #[prost(message, repeated, tag = "1")]
    pub findings: Vec<FindingProto>,
    #[prost(bool, tag = "2")]
    pub dry_run: bool,
}

/// Response from `Fix` RPC.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FixResponse {
    #[prost(message, repeated, tag = "1")]
    pub results: Vec<FixResultProto>,
}

/// Result of applying a single fix.
#[derive(Clone, PartialEq, prost::Message)]
pub struct FixResultProto {
    #[prost(string, tag = "1")]
    pub rule_id: String,
    #[prost(bool, tag = "2")]
    pub applied: bool,
    #[prost(message, repeated, tag = "3")]
    pub edits: Vec<TextEditProto>,
    #[prost(string, tag = "4")]
    pub reason: String,
}

// --- Conversion helpers between proto types and core diagnostic types ---

use chaffra_core::diagnostic::{
    Action, AnalysisResult, Finding, FixResult, Location, ModuleInfo, ModuleMetrics, Rule,
    RuleExplanation, Severity, TextEdit,
};

impl From<ModuleInfoProto> for ModuleInfo {
    fn from(p: ModuleInfoProto) -> Self {
        ModuleInfo {
            id: p.id,
            name: p.name,
            version: p.version,
            languages: p.languages,
            capabilities: p.capabilities,
            rules: p.rules.into_iter().map(Rule::from).collect(),
        }
    }
}

impl From<RuleInfoProto> for Rule {
    fn from(p: RuleInfoProto) -> Self {
        Rule {
            id: p.id,
            name: p.name,
            description: p.description,
            default_severity: Severity::from_str_loose(&p.default_severity)
                .unwrap_or(Severity::Warning),
            category: p.category,
        }
    }
}

impl From<FindingProto> for Finding {
    fn from(p: FindingProto) -> Self {
        Finding {
            rule_id: p.rule_id,
            message: p.message,
            severity: Severity::from_str_loose(&p.severity).unwrap_or(Severity::Warning),
            location: p.location.map(Location::from).unwrap_or(Location {
                file: String::new(),
                start_line: 0,
                end_line: 0,
                start_column: 0,
                end_column: 0,
            }),
            confidence: p.confidence,
            actions: p.actions.into_iter().map(Action::from).collect(),
            metadata: p.metadata,
        }
    }
}

impl From<LocationProto> for Location {
    fn from(p: LocationProto) -> Self {
        Location {
            file: p.file,
            start_line: p.start_line,
            end_line: p.end_line,
            start_column: p.start_column,
            end_column: p.end_column,
        }
    }
}

impl From<ActionProto> for Action {
    fn from(p: ActionProto) -> Self {
        Action {
            description: p.description,
            auto_fixable: p.auto_fixable,
            edits: p.edits.into_iter().map(TextEdit::from).collect(),
        }
    }
}

impl From<TextEditProto> for TextEdit {
    fn from(p: TextEditProto) -> Self {
        TextEdit {
            file: p.file,
            start_line: p.start_line,
            end_line: p.end_line,
            new_text: p.new_text,
        }
    }
}

impl From<AnalysisResponse> for AnalysisResult {
    fn from(p: AnalysisResponse) -> Self {
        let metrics = p.metrics.map(ModuleMetrics::from).unwrap_or(ModuleMetrics {
            files_analyzed: 0,
            duration_ms: 0,
            counters: HashMap::new(),
        });
        AnalysisResult {
            findings: p.findings.into_iter().map(Finding::from).collect(),
            metrics,
        }
    }
}

impl From<ModuleMetricsProto> for ModuleMetrics {
    fn from(p: ModuleMetricsProto) -> Self {
        ModuleMetrics {
            files_analyzed: p.files_analyzed,
            duration_ms: p.duration_ms,
            counters: p.counters,
        }
    }
}

impl From<ExplainResponse> for RuleExplanation {
    fn from(p: ExplainResponse) -> Self {
        RuleExplanation {
            rule_id: p.rule_id,
            name: p.name,
            description: p.description,
            rationale: p.rationale,
            default_severity: Severity::from_str_loose(&p.default_severity)
                .unwrap_or(Severity::Warning),
            suppression_syntax: p.suppression_syntax,
            examples: p.examples,
        }
    }
}

impl From<FixResultProto> for FixResult {
    fn from(p: FixResultProto) -> Self {
        FixResult {
            rule_id: p.rule_id,
            applied: p.applied,
            edits: p.edits.into_iter().map(TextEdit::from).collect(),
            reason: p.reason,
        }
    }
}

// --- Conversion from core types to proto (for sending requests) ---

impl From<&chaffra_core::diagnostic::FileInfo> for FileInfoProto {
    fn from(f: &chaffra_core::diagnostic::FileInfo) -> Self {
        FileInfoProto {
            path: f.path.clone(),
            content: f.content.clone(),
        }
    }
}

impl From<&Finding> for FindingProto {
    fn from(f: &Finding) -> Self {
        FindingProto {
            rule_id: f.rule_id.clone(),
            message: f.message.clone(),
            severity: f.severity.to_string(),
            location: Some(LocationProto {
                file: f.location.file.clone(),
                start_line: f.location.start_line,
                end_line: f.location.end_line,
                start_column: f.location.start_column,
                end_column: f.location.end_column,
            }),
            confidence: f.confidence,
            actions: f
                .actions
                .iter()
                .map(|a| ActionProto {
                    description: a.description.clone(),
                    auto_fixable: a.auto_fixable,
                    edits: a
                        .edits
                        .iter()
                        .map(|e| TextEditProto {
                            file: e.file.clone(),
                            start_line: e.start_line,
                            end_line: e.end_line,
                            new_text: e.new_text.clone(),
                        })
                        .collect(),
                })
                .collect(),
            metadata: f.metadata.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_module_info_conversion() {
        let proto = ModuleInfoProto {
            id: "test".to_owned(),
            name: "Test".to_owned(),
            version: "1.0".to_owned(),
            languages: vec!["go".to_owned()],
            capabilities: vec!["analyze".to_owned()],
            rules: vec![RuleInfoProto {
                id: "r1".to_owned(),
                name: "Rule 1".to_owned(),
                description: "desc".to_owned(),
                default_severity: "warning".to_owned(),
                category: "test".to_owned(),
            }],
        };
        let info: ModuleInfo = proto.into();
        assert_eq!(info.id, "test");
        assert_eq!(info.rules.len(), 1);
        assert_eq!(info.rules[0].default_severity, Severity::Warning);
    }

    #[test]
    fn test_finding_conversion() {
        let proto = FindingProto {
            rule_id: "r1".to_owned(),
            message: "msg".to_owned(),
            severity: "error".to_owned(),
            location: Some(LocationProto {
                file: "a.go".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 5,
            }),
            confidence: 0.9,
            actions: vec![],
            metadata: HashMap::new(),
        };
        let finding: Finding = proto.into();
        assert_eq!(finding.rule_id, "r1");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.location.file, "a.go");
    }

    #[test]
    fn test_finding_conversion_no_location() {
        let proto = FindingProto {
            rule_id: "r1".to_owned(),
            message: "msg".to_owned(),
            severity: "info".to_owned(),
            location: None,
            confidence: 0.5,
            actions: vec![],
            metadata: HashMap::new(),
        };
        let finding: Finding = proto.into();
        assert_eq!(finding.location.file, "");
    }

    #[test]
    fn test_analysis_response_conversion() {
        let proto = AnalysisResponse {
            findings: vec![],
            metrics: Some(ModuleMetricsProto {
                files_analyzed: 5,
                duration_ms: 100,
                counters: HashMap::new(),
            }),
        };
        let result: AnalysisResult = proto.into();
        assert_eq!(result.metrics.files_analyzed, 5);
        assert_eq!(result.metrics.duration_ms, 100);
    }

    #[test]
    fn test_analysis_response_no_metrics() {
        let proto = AnalysisResponse {
            findings: vec![],
            metrics: None,
        };
        let result: AnalysisResult = proto.into();
        assert_eq!(result.metrics.files_analyzed, 0);
    }

    #[test]
    fn test_explain_response_conversion() {
        let proto = ExplainResponse {
            rule_id: "r1".to_owned(),
            name: "Rule".to_owned(),
            description: "desc".to_owned(),
            rationale: "why".to_owned(),
            default_severity: "error".to_owned(),
            suppression_syntax: "// ignore".to_owned(),
            examples: vec!["ex1".to_owned()],
        };
        let explanation: RuleExplanation = proto.into();
        assert_eq!(explanation.rule_id, "r1");
        assert_eq!(explanation.default_severity, Severity::Error);
    }

    #[test]
    fn test_fix_result_conversion() {
        let proto = FixResultProto {
            rule_id: "r1".to_owned(),
            applied: true,
            edits: vec![TextEditProto {
                file: "a.go".to_owned(),
                start_line: 1,
                end_line: 2,
                new_text: "fixed".to_owned(),
            }],
            reason: "done".to_owned(),
        };
        let result: FixResult = proto.into();
        assert!(result.applied);
        assert_eq!(result.edits.len(), 1);
    }

    #[test]
    fn test_file_info_to_proto() {
        let fi = chaffra_core::diagnostic::FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        };
        let proto = FileInfoProto::from(&fi);
        assert_eq!(proto.path, "test.go");
        assert_eq!(proto.content, b"package main");
    }

    #[test]
    fn test_finding_to_proto_roundtrip() {
        let finding = Finding {
            rule_id: "test-rule".to_owned(),
            message: "test message".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 10,
            },
            confidence: 0.8,
            actions: vec![],
            metadata: HashMap::new(),
        };
        let proto = FindingProto::from(&finding);
        let back: Finding = proto.into();
        assert_eq!(back.rule_id, finding.rule_id);
        assert_eq!(back.severity, finding.severity);
    }
}
