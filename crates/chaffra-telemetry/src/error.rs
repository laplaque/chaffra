//! Error types for the telemetry crate.

use thiserror::Error;

/// Errors that can occur during telemetry operations.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// A metric with the given name was already registered.
    #[error("metric already registered: {0}")]
    MetricAlreadyRegistered(String),

    /// Backend configuration is invalid.
    #[error("invalid backend config: {0}")]
    InvalidBackendConfig(String),

    /// A telemetry audience value could not be parsed.
    #[error(
        "invalid telemetry audience: {0:?} (expected one of: on, off, user-only, operator-only)"
    )]
    InvalidAudience(String),

    /// Backend failed to flush or send data.
    #[error("backend error: {0}")]
    BackendError(String),

    /// I/O error writing telemetry data.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Convenience type alias.
pub type Result<T> = std::result::Result<T, TelemetryError>;
