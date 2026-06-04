//! Migrate configurations from other analysis tools to `.chaffra.toml`.
//!
//! Supported tools:
//! - **knip**: JS/TS dead code detection
//! - **jscpd**: Copy-paste detection
//! - **golangci-lint**: Go linter aggregator
//! - **ruff**: Python linter
//! - **import-linter**: Python import boundary enforcement

pub mod converters;

use std::path::Path;

/// Supported source tools for migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceTool {
    Knip,
    Jscpd,
    GolangciLint,
    Ruff,
    ImportLinter,
}

impl SourceTool {
    /// Parse a tool name from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "knip" => Some(SourceTool::Knip),
            "jscpd" => Some(SourceTool::Jscpd),
            "golangci-lint" | "golangci" => Some(SourceTool::GolangciLint),
            "ruff" => Some(SourceTool::Ruff),
            "import-linter" | "importlinter" => Some(SourceTool::ImportLinter),
            _ => None,
        }
    }

    /// Get the default config file name for this tool.
    pub fn default_config_file(&self) -> &'static str {
        match self {
            SourceTool::Knip => "knip.json",
            SourceTool::Jscpd => ".jscpd.json",
            SourceTool::GolangciLint => ".golangci.yml",
            SourceTool::Ruff => "ruff.toml",
            SourceTool::ImportLinter => ".importlinter",
        }
    }
}

impl std::fmt::Display for SourceTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceTool::Knip => write!(f, "knip"),
            SourceTool::Jscpd => write!(f, "jscpd"),
            SourceTool::GolangciLint => write!(f, "golangci-lint"),
            SourceTool::Ruff => write!(f, "ruff"),
            SourceTool::ImportLinter => write!(f, "import-linter"),
        }
    }
}

/// Errors from migration operations.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    #[error("unsupported source tool: {0}")]
    UnsupportedTool(String),
    #[error("config file not found: {0}")]
    ConfigNotFound(String),
    #[error("failed to read config: {0}")]
    ReadError(String),
    #[error("failed to parse config: {0}")]
    ParseError(String),
}

/// Result of a migration: the generated TOML and any notes.
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// Generated `.chaffra.toml` content.
    pub toml_content: String,
    /// Human-readable notes about what was mapped and what was not.
    pub notes: Vec<String>,
}

/// Run migration from the given tool's config in the specified directory.
pub fn migrate(tool: SourceTool, config_dir: &Path) -> Result<MigrationResult, MigrateError> {
    let config_path = config_dir.join(tool.default_config_file());

    // For tools that might embed config in pyproject.toml or package.json,
    // try the default path first, then fall back.
    let content = if config_path.exists() {
        std::fs::read_to_string(&config_path).map_err(|e| MigrateError::ReadError(e.to_string()))?
    } else {
        // Try alternative locations
        match tool {
            SourceTool::Ruff => {
                let alt = config_dir.join("pyproject.toml");
                if alt.exists() {
                    std::fs::read_to_string(&alt)
                        .map_err(|e| MigrateError::ReadError(e.to_string()))?
                } else {
                    return Err(MigrateError::ConfigNotFound(
                        config_path.display().to_string(),
                    ));
                }
            }
            SourceTool::Knip => {
                let alt = config_dir.join("package.json");
                if alt.exists() {
                    std::fs::read_to_string(&alt)
                        .map_err(|e| MigrateError::ReadError(e.to_string()))?
                } else {
                    return Err(MigrateError::ConfigNotFound(
                        config_path.display().to_string(),
                    ));
                }
            }
            _ => {
                return Err(MigrateError::ConfigNotFound(
                    config_path.display().to_string(),
                ));
            }
        }
    };

    match tool {
        SourceTool::Knip => converters::convert_knip(&content),
        SourceTool::Jscpd => converters::convert_jscpd(&content),
        SourceTool::GolangciLint => converters::convert_golangci_lint(&content),
        SourceTool::Ruff => converters::convert_ruff(&content),
        SourceTool::ImportLinter => converters::convert_import_linter(&content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_source_tool_from_str_loose() {
        let cases = vec![
            ("knip", Some(SourceTool::Knip)),
            ("jscpd", Some(SourceTool::Jscpd)),
            ("golangci-lint", Some(SourceTool::GolangciLint)),
            ("golangci", Some(SourceTool::GolangciLint)),
            ("ruff", Some(SourceTool::Ruff)),
            ("import-linter", Some(SourceTool::ImportLinter)),
            ("importlinter", Some(SourceTool::ImportLinter)),
            ("unknown", None),
        ];
        for (input, expected) in cases {
            assert_eq!(
                SourceTool::from_str_loose(input),
                expected,
                "input: {input}"
            );
        }
    }

    #[test]
    fn test_source_tool_display() {
        let cases = vec![
            (SourceTool::Knip, "knip"),
            (SourceTool::Jscpd, "jscpd"),
            (SourceTool::GolangciLint, "golangci-lint"),
            (SourceTool::Ruff, "ruff"),
            (SourceTool::ImportLinter, "import-linter"),
        ];
        for (tool, expected) in cases {
            assert_eq!(tool.to_string(), expected);
        }
    }

    #[test]
    fn test_default_config_file() {
        assert_eq!(SourceTool::Knip.default_config_file(), "knip.json");
        assert_eq!(SourceTool::Jscpd.default_config_file(), ".jscpd.json");
        assert_eq!(
            SourceTool::GolangciLint.default_config_file(),
            ".golangci.yml"
        );
        assert_eq!(SourceTool::Ruff.default_config_file(), "ruff.toml");
        assert_eq!(
            SourceTool::ImportLinter.default_config_file(),
            ".importlinter"
        );
    }

    #[test]
    fn test_migrate_config_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = migrate(SourceTool::GolangciLint, dir.path());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MigrateError::ConfigNotFound(_)
        ));
    }

    #[test]
    fn test_migrate_error_display() {
        let err = MigrateError::UnsupportedTool("foo".to_owned());
        assert_eq!(err.to_string(), "unsupported source tool: foo");

        let err = MigrateError::ConfigNotFound("bar.json".to_owned());
        assert_eq!(err.to_string(), "config file not found: bar.json");
    }
}
