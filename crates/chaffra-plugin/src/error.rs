//! Error types for the plugin host.

use thiserror::Error;

/// Errors from the plugin host subsystem.
#[derive(Debug, Error)]
pub enum PluginError {
    /// gRPC transport error.
    #[error("gRPC transport error: {0}")]
    Transport(String),

    /// The external module process failed to start.
    #[error("failed to spawn module process '{command}': {reason}")]
    SpawnFailed { command: String, reason: String },

    /// The module process exited unexpectedly.
    #[error("module process exited unexpectedly")]
    ProcessExited,

    /// Docker is not available.
    #[error("docker is not available: {0}")]
    DockerUnavailable(String),

    /// Invalid plugin configuration.
    #[error("invalid plugin config: {0}")]
    Config(String),

    /// Connection timed out.
    #[error("connection to module at {endpoint} timed out")]
    ConnectionTimeout { endpoint: String },
}
