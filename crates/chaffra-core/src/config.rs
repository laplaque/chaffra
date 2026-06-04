//! Configuration loading from `.chaffra.toml`.

use crate::error::{ChaffraError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Top-level chaffra configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChaffraConfig {
    /// Project-level settings.
    #[serde(default)]
    pub project: ProjectConfig,

    /// Per-rule severity overrides.
    #[serde(default)]
    pub rules: HashMap<String, String>,

    /// Health scoring thresholds.
    #[serde(default)]
    pub health: HealthConfig,

    /// Architecture boundary settings.
    #[serde(default)]
    pub boundaries: BoundaryConfig,

    /// Duplication detection settings.
    #[serde(default)]
    pub duplication: DuplicationConfig,

    /// Audit settings.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Framework awareness settings.
    #[serde(default)]
    pub framework: FrameworkConfig,

    /// Per-module config sections (arbitrary key-value).
    #[serde(default)]
    pub modules: HashMap<String, HashMap<String, toml::Value>>,
}

/// Project-level configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectConfig {
    /// Glob patterns for entry point files.
    #[serde(default)]
    pub entry: Vec<String>,

    /// Glob patterns for files/directories to ignore.
    #[serde(default)]
    pub ignore: Vec<String>,
}

/// Health scoring configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Maximum cyclomatic complexity before penalty.
    #[serde(default = "default_max_cyclomatic", rename = "max-cyclomatic")]
    pub max_cyclomatic: u32,

    /// Maximum cognitive complexity before penalty.
    #[serde(default = "default_max_cognitive", rename = "max-cognitive")]
    pub max_cognitive: u32,

    /// Minimum passing health score.
    #[serde(default = "default_min_score", rename = "min-score")]
    pub min_score: u32,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            max_cyclomatic: default_max_cyclomatic(),
            max_cognitive: default_max_cognitive(),
            min_score: default_min_score(),
        }
    }
}

fn default_max_cyclomatic() -> u32 {
    20
}
fn default_max_cognitive() -> u32 {
    15
}
fn default_min_score() -> u32 {
    70
}

/// Architecture boundary configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BoundaryConfig {
    /// Preset name.
    pub preset: Option<String>,

    /// Custom zone definitions.
    #[serde(default)]
    pub zones: Vec<ZoneDefinition>,

    /// Custom dependency rules.
    #[serde(default)]
    pub rules: Vec<DependencyRule>,
}

/// A named zone with glob patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneDefinition {
    pub name: String,
    pub patterns: Vec<String>,
}

/// A dependency rule between zones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRule {
    pub from: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Duplication detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicationConfig {
    /// Minimum tokens for a duplicate match.
    #[serde(default = "default_min_tokens", rename = "min-tokens")]
    pub min_tokens: u32,

    /// Detection mode.
    #[serde(default = "default_dup_mode")]
    pub mode: String,
}

impl Default for DuplicationConfig {
    fn default() -> Self {
        Self {
            min_tokens: default_min_tokens(),
            mode: default_dup_mode(),
        }
    }
}

fn default_min_tokens() -> u32 {
    50
}
fn default_dup_mode() -> String {
    "mild".to_owned()
}

/// Audit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Gating mode: "new-only" or "all".
    #[serde(default = "default_audit_gate")]
    pub gate: String,

    /// Tolerance threshold, e.g. "2%".
    #[serde(default = "default_audit_tolerance")]
    pub tolerance: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            gate: default_audit_gate(),
            tolerance: default_audit_tolerance(),
        }
    }
}

fn default_audit_gate() -> String {
    "new-only".to_owned()
}
fn default_audit_tolerance() -> String {
    "2%".to_owned()
}

/// Framework awareness configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrameworkConfig {
    /// Go framework list.
    #[serde(default)]
    pub go: Vec<String>,

    /// Python framework list.
    #[serde(default)]
    pub python: Vec<String>,
}

/// Default configuration file name.
pub const CONFIG_FILE_NAME: &str = ".chaffra.toml";

/// Example configuration template.
pub const CONFIG_TEMPLATE: &str = r#"# chaffra configuration
# See https://github.com/laplaque/chaffra for documentation

[project]
# Entry points — files where analysis starts
# entry = ["cmd/*/main.go", "src/**/*.py"]

# Files/directories to ignore
# ignore = ["vendor/**", "**/*_test.go", "**/__pycache__/**"]

[rules]
# Per-rule severity: "error" | "warn" | "off"
# unused-function = "error"
# unused-type = "warn"
# unused-import = "error"
# unused-file = "warn"
# high-cyclomatic = "warn"
# high-cognitive = "warn"

[health]
# Complexity thresholds
# max-cyclomatic = 20
# max-cognitive = 15
# min-score = 70

[modules]
# Per-module configuration
# [modules.dead-code]
# extra-entry-patterns = ["Handle*"]
#
# [modules.complexity]
# cyclomatic-threshold = 15
"#;

impl ChaffraConfig {
    /// Load configuration from a file path.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            ChaffraError::Config(format!("failed to read {}: {}", path.display(), e))
        })?;
        Self::parse(&content)
    }

    /// Load configuration from the given directory, looking for `.chaffra.toml`.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let config_path = dir.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            Self::load(&config_path)
        } else {
            Ok(Self::default())
        }
    }

    /// Parse configuration from a TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(|e| ChaffraError::Config(format!("invalid TOML: {e}")))
    }

    /// Get the per-module config section, if any.
    pub fn module_config(&self, module_id: &str) -> HashMap<String, String> {
        self.modules
            .get(module_id)
            .map(|m| {
                m.iter()
                    .map(|(k, v)| {
                        let value = match v {
                            toml::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        (k.clone(), value)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ChaffraConfig::default();
        assert_eq!(config.health.max_cyclomatic, 20);
        assert_eq!(config.health.max_cognitive, 15);
        assert_eq!(config.health.min_score, 70);
    }

    #[test]
    fn test_parse_empty_toml() {
        let config = ChaffraConfig::parse("").unwrap();
        assert_eq!(config.health.max_cyclomatic, 20);
    }

    #[test]
    fn test_parse_config_with_rules() {
        let toml = r#"
[rules]
unused-function = "error"
unused-type = "warn"

[health]
max-cyclomatic = 15
"#;
        let config = ChaffraConfig::parse(toml).unwrap();
        assert_eq!(
            config.rules.get("unused-function").map(String::as_str),
            Some("error")
        );
        assert_eq!(config.health.max_cyclomatic, 15);
    }

    #[test]
    fn test_parse_config_with_modules() {
        let toml = r#"
[modules.dead-code]
extra-entry-patterns = ["Handle*"]
"#;
        let config = ChaffraConfig::parse(toml).unwrap();
        assert!(config.modules.contains_key("dead-code"));
    }

    #[test]
    fn test_module_config_extraction() {
        let toml = r#"
[modules.dead-code]
threshold = "10"
"#;
        let config = ChaffraConfig::parse(toml).unwrap();
        let mc = config.module_config("dead-code");
        assert!(mc.contains_key("threshold"));
    }

    #[test]
    fn test_missing_module_config() {
        let config = ChaffraConfig::default();
        let mc = config.module_config("nonexistent");
        assert!(mc.is_empty());
    }

    #[test]
    fn test_config_template_parses() {
        let config = ChaffraConfig::parse(CONFIG_TEMPLATE).unwrap();
        // Template has all values commented out, so defaults apply
        assert_eq!(config.health.max_cyclomatic, 20);
    }
}
