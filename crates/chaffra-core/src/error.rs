//! Error types for chaffra-core.

use thiserror::Error;

/// Errors that can occur across chaffra core operations.
#[derive(Debug, Error)]
pub enum ChaffraError {
    /// A module with the given ID was not found.
    #[error("module not found: {0}")]
    ModuleNotFound(String),

    /// A module with the given ID is already registered.
    #[error("module already registered: {0}")]
    ModuleAlreadyRegistered(String),

    /// A rule with the given ID was not found.
    #[error("rule not found: {0}")]
    RuleNotFound(String),

    /// Configuration file could not be loaded or parsed.
    #[error("config error: {0}")]
    Config(String),

    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A serialization/deserialization error occurred.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Analysis encountered an error.
    #[error("analysis error: {0}")]
    Analysis(String),

    /// A proto response was malformed or missing required fields.
    #[error("proto conversion error: {0}")]
    ProtoConversion(String),

    /// Parse error from tree-sitter or other parser.
    #[error("parse error: {0}")]
    Parse(String),
}

/// Convenience type alias for results using [`ChaffraError`].
pub type Result<T> = std::result::Result<T, ChaffraError>;
