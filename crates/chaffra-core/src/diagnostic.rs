//! Diagnostic types: findings, severity, rules, locations, and languages.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Severity level for a diagnostic finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding, no action required.
    Info,
    /// Warning -- should be addressed but not blocking.
    Warning,
    /// Error -- must be addressed, blocks CI gates.
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

impl Severity {
    /// Parse a severity from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "warning" | "warn" => Some(Severity::Warning),
            "error" | "err" => Some(Severity::Error),
            "off" => None,
            _ => None,
        }
    }
}

/// A programming language supported by chaffra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Go,
    Python,
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Language::Go => write!(f, "go"),
            Language::Python => write!(f, "python"),
        }
    }
}

impl Language {
    /// Detect language from a file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "go" => Some(Language::Go),
            "py" => Some(Language::Python),
            _ => None,
        }
    }
}

/// Unique identifier for a module.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModuleId(pub String);

impl fmt::Display for ModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ModuleId {
    pub fn new(id: &str) -> Self {
        Self(id.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A rule definition within a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier, e.g. "unused-function".
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this rule detects.
    pub description: String,
    /// Default severity if not overridden by config.
    pub default_severity: Severity,
    /// Category grouping (e.g. "dead-code", "complexity").
    pub category: String,
}

/// Source location for a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path relative to the analysis root.
    pub file: String,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// 0-based start column.
    pub start_column: u32,
    /// 0-based end column.
    pub end_column: u32,
}

/// A text edit for auto-fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEdit {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub new_text: String,
}

/// An available action to fix a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub description: String,
    pub auto_fixable: bool,
    pub edits: Vec<TextEdit>,
}

/// A single diagnostic finding produced by an analysis module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The rule that triggered this finding.
    pub rule_id: String,
    /// Human-readable message.
    pub message: String,
    /// Severity of this specific finding.
    pub severity: Severity,
    /// Source location.
    pub location: Location,
    /// Confidence score from 0.0 to 1.0.
    pub confidence: f32,
    /// Available fix actions.
    pub actions: Vec<Action>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

/// Information about a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub languages: Vec<String>,
    pub capabilities: Vec<String>,
    pub rules: Vec<Rule>,
}

/// Metrics from an analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetrics {
    pub files_analyzed: u64,
    pub duration_ms: u64,
    pub counters: HashMap<String, u64>,
}

/// Result of an analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub metrics: ModuleMetrics,
}

/// Explanation of a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExplanation {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub rationale: String,
    pub default_severity: Severity,
    pub suppression_syntax: String,
    pub examples: Vec<String>,
}

/// Result of applying a fix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixResult {
    pub rule_id: String,
    pub applied: bool,
    pub edits: Vec<TextEdit>,
    pub reason: String,
}

/// File information passed to analysis modules.
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// File path relative to analysis root.
    pub path: String,
    /// Raw file content.
    pub content: Vec<u8>,
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

/// Per-file health score.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectHealth {
    pub score: u32,
    pub grade: HealthGrade,
    pub files: Vec<FileHealthScore>,
    pub total_files: u64,
}
