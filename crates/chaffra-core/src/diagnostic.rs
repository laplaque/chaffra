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
    Php,
    Dart,
    CSharp,
    Rust,
    JavaScript,
    TypeScript,
    Java,
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Language::Go => write!(f, "go"),
            Language::Python => write!(f, "python"),
            Language::Php => write!(f, "php"),
            Language::Dart => write!(f, "dart"),
            Language::CSharp => write!(f, "csharp"),
            Language::Rust => write!(f, "rust"),
            Language::JavaScript => write!(f, "javascript"),
            Language::TypeScript => write!(f, "typescript"),
            Language::Java => write!(f, "java"),
        }
    }
}

impl Language {
    /// Detect language from a file extension.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "go" => Some(Language::Go),
            "py" => Some(Language::Python),
            "php" => Some(Language::Php),
            "dart" => Some(Language::Dart),
            "cs" => Some(Language::CSharp),
            "rs" => Some(Language::Rust),
            "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
            "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
            "java" => Some(Language::Java),
            _ => None,
        }
    }

    /// Whether this language has full tree-sitter grammar support.
    pub fn has_tree_sitter_grammar(&self) -> bool {
        matches!(
            self,
            Language::Go
                | Language::Python
                | Language::JavaScript
                | Language::TypeScript
                | Language::Java
        )
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

/// An inline metric data point returned by a module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InlineMetric {
    pub name: String,
    pub value: f64,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub user_scoped: bool,
}

/// An inline span returned by a module.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InlineSpan {
    pub name: String,
    #[serde(default)]
    pub trace_id: String,
    #[serde(default)]
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: String,
    #[serde(default)]
    pub start_time_ms: u64,
    #[serde(default)]
    pub end_time_ms: u64,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    #[serde(default)]
    pub status: String,
}

/// Metrics from an analysis run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleMetrics {
    pub files_analyzed: u64,
    pub duration_ms: u64,
    pub counters: HashMap<String, u64>,
    #[serde(default)]
    pub inline_metrics: Vec<InlineMetric>,
    #[serde(default)]
    pub inline_spans: Vec<InlineSpan>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_display() {
        let cases = vec![
            (Severity::Info, "info"),
            (Severity::Warning, "warning"),
            (Severity::Error, "error"),
        ];
        for (sev, expected) in cases {
            assert_eq!(sev.to_string(), expected);
        }
    }

    #[test]
    fn test_severity_from_str_loose() {
        let cases = vec![
            ("info", Some(Severity::Info)),
            ("warning", Some(Severity::Warning)),
            ("warn", Some(Severity::Warning)),
            ("error", Some(Severity::Error)),
            ("err", Some(Severity::Error)),
            ("off", None),
            ("bogus", None),
        ];
        for (input, expected) in cases {
            assert_eq!(Severity::from_str_loose(input), expected, "input: {input}");
        }
    }

    #[test]
    fn test_language_display() {
        assert_eq!(Language::Go.to_string(), "go");
        assert_eq!(Language::Python.to_string(), "python");
        assert_eq!(Language::Php.to_string(), "php");
        assert_eq!(Language::Dart.to_string(), "dart");
        assert_eq!(Language::CSharp.to_string(), "csharp");
        assert_eq!(Language::Rust.to_string(), "rust");
        assert_eq!(Language::JavaScript.to_string(), "javascript");
        assert_eq!(Language::TypeScript.to_string(), "typescript");
        assert_eq!(Language::Java.to_string(), "java");
    }

    #[test]
    fn test_language_from_extension() {
        let cases = vec![
            ("go", Some(Language::Go)),
            ("py", Some(Language::Python)),
            ("php", Some(Language::Php)),
            ("dart", Some(Language::Dart)),
            ("cs", Some(Language::CSharp)),
            ("rs", Some(Language::Rust)),
            ("js", Some(Language::JavaScript)),
            ("jsx", Some(Language::JavaScript)),
            ("ts", Some(Language::TypeScript)),
            ("tsx", Some(Language::TypeScript)),
            ("java", Some(Language::Java)),
            ("txt", None),
        ];
        for (ext, expected) in cases {
            assert_eq!(Language::from_extension(ext), expected, "ext: {ext}");
        }
    }

    #[test]
    fn test_language_has_tree_sitter_grammar() {
        assert!(Language::Go.has_tree_sitter_grammar());
        assert!(Language::Python.has_tree_sitter_grammar());
        assert!(Language::JavaScript.has_tree_sitter_grammar());
        assert!(Language::TypeScript.has_tree_sitter_grammar());
        assert!(Language::Java.has_tree_sitter_grammar());
        assert!(!Language::Php.has_tree_sitter_grammar());
        assert!(!Language::Dart.has_tree_sitter_grammar());
        assert!(!Language::CSharp.has_tree_sitter_grammar());
        assert!(!Language::Rust.has_tree_sitter_grammar());
    }

    #[test]
    fn test_module_id() {
        let id = ModuleId::new("dead-code");
        assert_eq!(id.as_str(), "dead-code");
        assert_eq!(id.to_string(), "dead-code");
    }

    #[test]
    fn test_health_grade_from_score() {
        let cases = vec![
            (100, HealthGrade::A),
            (95, HealthGrade::A),
            (90, HealthGrade::A),
            (89, HealthGrade::B),
            (80, HealthGrade::B),
            (79, HealthGrade::C),
            (70, HealthGrade::C),
            (69, HealthGrade::D),
            (60, HealthGrade::D),
            (59, HealthGrade::F),
            (0, HealthGrade::F),
        ];
        for (score, expected) in cases {
            assert_eq!(HealthGrade::from_score(score), expected, "score: {score}");
        }
    }

    #[test]
    fn test_health_grade_display() {
        let cases = vec![
            (HealthGrade::A, "A"),
            (HealthGrade::B, "B"),
            (HealthGrade::C, "C"),
            (HealthGrade::D, "D"),
            (HealthGrade::F, "F"),
        ];
        for (grade, expected) in cases {
            assert_eq!(grade.to_string(), expected);
        }
    }
}
