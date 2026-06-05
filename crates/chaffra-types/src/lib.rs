// TODO(#19): coverage gate unenforceable until CI tooling lands

//! Typed output contract for downstream consumers of chaffra analysis.
//!
//! This crate publishes stable, serializable types that external tools, CI
//! integrations, and dashboards can depend on without pulling in chaffra
//! internals. All types derive `Serialize`, `Deserialize`, `Debug`, `Clone`,
//! and `PartialEq`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Severity level for a diagnostic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

/// Source location for a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_column: u32,
    pub end_column: u32,
}

/// A text edit for auto-fix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextEdit {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub new_text: String,
}

/// An available action to fix a finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub description: String,
    pub auto_fixable: bool,
    pub edits: Vec<TextEdit>,
}

/// A single diagnostic finding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub message: String,
    pub severity: Severity,
    pub location: Location,
    pub confidence: f32,
    pub actions: Vec<Action>,
    pub metadata: HashMap<String, String>,
}

/// Health grade letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthGrade {
    A,
    B,
    C,
    D,
    F,
}

impl fmt::Display for HealthGrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthGrade::A => write!(f, "A"),
            HealthGrade::B => write!(f, "B"),
            HealthGrade::C => write!(f, "C"),
            HealthGrade::D => write!(f, "D"),
            HealthGrade::F => write!(f, "F"),
        }
    }
}

impl HealthGrade {
    /// Derive a grade from a 0-100 score.
    pub fn from_score(score: u32) -> Self {
        match score {
            90..=100 => HealthGrade::A,
            80..=89 => HealthGrade::B,
            70..=79 => HealthGrade::C,
            60..=69 => HealthGrade::D,
            _ => HealthGrade::F,
        }
    }
}

/// Per-file health score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileHealthScore {
    pub file: String,
    pub score: u32,
    pub grade: HealthGrade,
    pub cyclomatic_penalty: u32,
    pub cognitive_penalty: u32,
    pub size_penalty: u32,
    pub nesting_penalty: u32,
}

/// Project-level health summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProjectHealth {
    pub score: u32,
    pub grade: HealthGrade,
    pub files: Vec<FileHealthScore>,
    pub total_files: u64,
}

/// Module metrics from an analysis run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    pub files_analyzed: u64,
    pub duration_ms: u64,
    pub counters: HashMap<String, u64>,
}

/// Full analysis result with findings and metrics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisOutput {
    pub findings: Vec<Finding>,
    pub metrics: AnalysisMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ProjectHealth>,
}

/// Shields.io-compatible badge JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BadgeResponse {
    pub schema_version: u32,
    pub label: String,
    pub message: String,
    pub color: String,
}

impl BadgeResponse {
    /// Create a health badge from a score.
    pub fn from_health_score(score: u32) -> Self {
        let color = if score >= 80 {
            "green"
        } else if score >= 60 {
            "yellow"
        } else {
            "red"
        };
        Self {
            schema_version: 1,
            label: "chaffra health".to_owned(),
            message: format!("{score}%"),
            color: color.to_owned(),
        }
    }
}

/// Rule explanation for the explain command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleExplanation {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub rationale: String,
    pub default_severity: Severity,
    pub suppression_syntax: String,
    pub examples: Vec<String>,
}

/// Information about a registered module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub languages: Vec<String>,
    pub capabilities: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Info.to_string(), "info");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Error.to_string(), "error");
    }

    #[test]
    fn test_health_grade_from_score() {
        let cases = vec![
            (100, HealthGrade::A),
            (90, HealthGrade::A),
            (85, HealthGrade::B),
            (80, HealthGrade::B),
            (75, HealthGrade::C),
            (70, HealthGrade::C),
            (65, HealthGrade::D),
            (60, HealthGrade::D),
            (50, HealthGrade::F),
            (0, HealthGrade::F),
        ];
        for (score, expected) in cases {
            assert_eq!(HealthGrade::from_score(score), expected, "score: {score}");
        }
    }

    #[test]
    fn test_health_grade_display() {
        assert_eq!(HealthGrade::A.to_string(), "A");
        assert_eq!(HealthGrade::F.to_string(), "F");
    }

    #[test]
    fn test_badge_from_health_score_green() {
        let badge = BadgeResponse::from_health_score(90);
        assert_eq!(badge.color, "green");
        assert_eq!(badge.message, "90%");
        assert_eq!(badge.schema_version, 1);
        assert_eq!(badge.label, "chaffra health");
    }

    #[test]
    fn test_badge_from_health_score_yellow() {
        let badge = BadgeResponse::from_health_score(70);
        assert_eq!(badge.color, "yellow");
        assert_eq!(badge.message, "70%");
    }

    #[test]
    fn test_badge_from_health_score_red() {
        let badge = BadgeResponse::from_health_score(50);
        assert_eq!(badge.color, "red");
        assert_eq!(badge.message, "50%");
    }

    #[test]
    fn test_badge_boundary_80() {
        let badge = BadgeResponse::from_health_score(80);
        assert_eq!(badge.color, "green");
    }

    #[test]
    fn test_badge_boundary_60() {
        let badge = BadgeResponse::from_health_score(60);
        assert_eq!(badge.color, "yellow");
    }

    #[test]
    fn test_badge_boundary_59() {
        let badge = BadgeResponse::from_health_score(59);
        assert_eq!(badge.color, "red");
    }

    #[test]
    fn test_finding_serialization_roundtrip() {
        let finding = Finding {
            rule_id: "unused-function".to_owned(),
            message: "function `foo` is unused".to_owned(),
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
        };
        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding, deserialized);
    }

    #[test]
    fn test_badge_serialization() {
        let badge = BadgeResponse::from_health_score(85);
        let json = serde_json::to_string(&badge).unwrap();
        assert!(json.contains("schemaVersion"));
        assert!(json.contains("chaffra health"));
        let deserialized: BadgeResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(badge, deserialized);
    }

    #[test]
    fn test_analysis_output_serialization() {
        let output = AnalysisOutput {
            findings: vec![],
            metrics: AnalysisMetrics {
                files_analyzed: 10,
                duration_ms: 42,
                counters: HashMap::new(),
            },
            health: Some(ProjectHealth {
                score: 85,
                grade: HealthGrade::B,
                files: vec![],
                total_files: 10,
            }),
        };
        let json = serde_json::to_string(&output).unwrap();
        let deserialized: AnalysisOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, deserialized);
    }

    #[test]
    fn test_analysis_output_no_health() {
        let output = AnalysisOutput {
            findings: vec![],
            metrics: AnalysisMetrics {
                files_analyzed: 0,
                duration_ms: 0,
                counters: HashMap::new(),
            },
            health: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains("health"));
    }

    #[test]
    fn test_module_info_roundtrip() {
        let info = ModuleInfo {
            id: "dead-code".to_owned(),
            name: "Dead Code Detector".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: ModuleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_rule_explanation_roundtrip() {
        let explanation = RuleExplanation {
            rule_id: "unused-function".to_owned(),
            name: "Unused function".to_owned(),
            description: "Detects functions that are never called".to_owned(),
            rationale: "Dead code increases maintenance burden".to_owned(),
            default_severity: Severity::Warning,
            suppression_syntax: "// chaffra:ignore unused-function".to_owned(),
            examples: vec!["func unused() {}".to_owned()],
        };
        let json = serde_json::to_string(&explanation).unwrap();
        let deserialized: RuleExplanation = serde_json::from_str(&json).unwrap();
        assert_eq!(explanation, deserialized);
    }
}
