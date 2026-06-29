//! Telemetry backend sink implementations.
//!
//! Each backend receives a `ProjectedSnapshot` — a `TelemetrySnapshot` that
//! has been filtered through a specific audience — and writes it to the
//! appropriate target (file, stderr, HTTP endpoint, etc.). The newtype is
//! the structural fix R5 added: callers cannot pass a raw, unprojected
//! snapshot to a backend, because the only way to construct a
//! `ProjectedSnapshot` is via `TelemetrySnapshot::project_for_audience`.

pub mod cloudwatch;
pub mod json_file;
pub mod otlp;
pub mod prometheus;
pub mod statsd;
pub mod stderr;

use crate::collector::ProjectedSnapshot;
use crate::config::{BackendConfig, BackendKind};
use crate::error::{Result, TelemetryError};

/// Trait for telemetry backends that receive metric snapshots.
pub trait TelemetryBackend: Send + Sync + std::fmt::Debug {
    /// Backend name for status reporting.
    fn name(&self) -> &str;

    /// Flush the given audience-projected snapshot to this backend.
    fn flush(&self, snapshot: &ProjectedSnapshot) -> Result<()>;

    /// Test connectivity (used by `chaffra telemetry test`).
    fn test_connection(&self) -> Result<String>;

    /// Generate a dry-run payload preview (used by `chaffra telemetry inspect`).
    fn inspect(&self, snapshot: &ProjectedSnapshot) -> Result<String>;
}

/// Create a backend from its configuration.
pub fn create_backend(config: &BackendConfig) -> Result<Box<dyn TelemetryBackend>> {
    match config.kind {
        BackendKind::JsonFile => {
            let path = config
                .path
                .clone()
                .unwrap_or_else(|| "chaffra-telemetry.json".to_owned());
            Ok(Box::new(json_file::JsonFileBackend::new(path)))
        }
        BackendKind::Stderr => Ok(Box::new(stderr::StderrBackend::new())),
        BackendKind::Prometheus => {
            let port = config
                .options
                .get("port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(9090);
            Ok(Box::new(prometheus::PrometheusBackend::new(port)))
        }
        BackendKind::Otlp => {
            let endpoint = config
                .endpoint
                .clone()
                .unwrap_or_else(|| "http://localhost:4317".to_owned());
            Ok(Box::new(otlp::OtlpBackend::new(endpoint)))
        }
        BackendKind::Statsd => {
            let endpoint = config
                .endpoint
                .clone()
                .unwrap_or_else(|| "127.0.0.1:8125".to_owned());
            Ok(Box::new(statsd::StatsdBackend::new(endpoint)))
        }
        BackendKind::CloudWatch => {
            #[cfg(feature = "cloudwatch")]
            {
                let namespace = config
                    .options
                    .get("namespace")
                    .cloned()
                    .unwrap_or_else(|| "chaffra".to_owned());
                let region = config.options.get("region").cloned();
                Ok(Box::new(cloudwatch::CloudWatchBackend::new(
                    namespace, region,
                )))
            }
            #[cfg(not(feature = "cloudwatch"))]
            {
                Err(TelemetryError::InvalidBackendConfig(
                    "CloudWatch backend requires the 'cloudwatch' feature flag".to_owned(),
                ))
            }
        }
    }
}

/// Status information for a backend.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BackendStatus {
    pub name: String,
    pub kind: String,
    pub connected: bool,
    pub message: String,
}

/// Create all backends from configuration and return their status.
pub fn create_backends(
    configs: &[BackendConfig],
) -> (Vec<Box<dyn TelemetryBackend>>, Vec<BackendStatus>) {
    let mut backends = Vec::new();
    let mut statuses = Vec::new();

    for config in configs {
        match create_backend(config) {
            Ok(backend) => {
                let status = match backend.test_connection() {
                    Ok(msg) => BackendStatus {
                        name: backend.name().to_owned(),
                        kind: format!("{:?}", config.kind),
                        connected: true,
                        message: msg,
                    },
                    Err(e) => BackendStatus {
                        name: backend.name().to_owned(),
                        kind: format!("{:?}", config.kind),
                        connected: false,
                        message: e.to_string(),
                    },
                };
                statuses.push(status);
                backends.push(backend);
            }
            Err(e) => {
                statuses.push(BackendStatus {
                    name: format!("{:?}", config.kind),
                    kind: format!("{:?}", config.kind),
                    connected: false,
                    message: e.to_string(),
                });
            }
        }
    }

    (backends, statuses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BackendKind;
    use std::collections::HashMap;

    #[test]
    fn test_create_json_file_backend() {
        let config = BackendConfig {
            kind: BackendKind::JsonFile,
            endpoint: None,
            path: Some("/tmp/test-telemetry.json".to_owned()),
            options: HashMap::new(),
        };
        let backend = create_backend(&config).unwrap();
        assert_eq!(backend.name(), "json-file");
    }

    #[test]
    fn test_create_stderr_backend() {
        let config = BackendConfig {
            kind: BackendKind::Stderr,
            endpoint: None,
            path: None,
            options: HashMap::new(),
        };
        let backend = create_backend(&config).unwrap();
        assert_eq!(backend.name(), "stderr");
    }

    #[test]
    fn test_create_prometheus_backend() {
        let config = BackendConfig {
            kind: BackendKind::Prometheus,
            endpoint: None,
            path: None,
            options: HashMap::new(),
        };
        let backend = create_backend(&config).unwrap();
        assert_eq!(backend.name(), "prometheus");
    }

    #[test]
    fn test_create_otlp_backend() {
        let config = BackendConfig {
            kind: BackendKind::Otlp,
            endpoint: Some("http://localhost:4317".to_owned()),
            path: None,
            options: HashMap::new(),
        };
        let backend = create_backend(&config).unwrap();
        assert_eq!(backend.name(), "otlp");
    }

    #[test]
    fn test_create_statsd_backend() {
        let config = BackendConfig {
            kind: BackendKind::Statsd,
            endpoint: Some("127.0.0.1:8125".to_owned()),
            path: None,
            options: HashMap::new(),
        };
        let backend = create_backend(&config).unwrap();
        assert_eq!(backend.name(), "statsd");
    }

    #[test]
    fn test_create_cloudwatch_backend_without_feature() {
        let config = BackendConfig {
            kind: BackendKind::CloudWatch,
            endpoint: None,
            path: None,
            options: HashMap::new(),
        };
        // Without the `cloudwatch` feature, this should fail.
        #[cfg(not(feature = "cloudwatch"))]
        assert!(create_backend(&config).is_err());
    }

    #[test]
    fn test_create_backends_mixed() {
        let configs = vec![
            BackendConfig {
                kind: BackendKind::JsonFile,
                endpoint: None,
                path: Some("/tmp/test.json".to_owned()),
                options: HashMap::new(),
            },
            BackendConfig {
                kind: BackendKind::Stderr,
                endpoint: None,
                path: None,
                options: HashMap::new(),
            },
        ];
        let (backends, statuses) = create_backends(&configs);
        assert_eq!(backends.len(), 2);
        assert_eq!(statuses.len(), 2);
    }
}
