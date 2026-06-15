//! Telemetry configuration types.
//!
//! Maps to the `[modules.telemetry]` section in `.chaffra.toml`.

use crate::sampling::SamplingStrategy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Which telemetry audiences are enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryAudience {
    /// Both user-facing and operator metrics.
    On,
    /// All telemetry disabled.
    Off,
    /// Only user-facing metrics (finding counts, durations in output).
    #[default]
    UserOnly,
    /// Only operator metrics (backend sinks, no output decoration).
    OperatorOnly,
}

impl TelemetryAudience {
    /// Parse from a CLI flag value.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "on" | "true" | "1" => Some(Self::On),
            "off" | "false" | "0" => Some(Self::Off),
            "user-only" | "user_only" | "user" => Some(Self::UserOnly),
            "operator-only" | "operator_only" | "operator" => Some(Self::OperatorOnly),
            _ => None,
        }
    }

    /// Whether user-facing metrics should be emitted.
    pub fn user_enabled(self) -> bool {
        matches!(self, Self::On | Self::UserOnly)
    }

    /// Whether operator metrics should be sunk to backends.
    pub fn operator_enabled(self) -> bool {
        matches!(self, Self::On | Self::OperatorOnly)
    }
}

/// Kind of telemetry backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    /// Write JSON to `chaffra-telemetry.json` after each run.
    JsonFile,
    /// Structured JSON lines to stderr for CI ingestion.
    Stderr,
    /// Prometheus exposition format on `/metrics` endpoint (watch/server mode).
    Prometheus,
    /// OTLP gRPC export to an OTLP-compatible collector.
    Otlp,
    /// StatsD UDP push.
    Statsd,
    /// AWS CloudWatch PutMetricData (behind `cloudwatch` feature flag).
    CloudWatch,
}

impl BackendKind {
    /// Parse from a CLI flag value.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "json-file" | "json" | "file" => Some(Self::JsonFile),
            "stderr" | "log" => Some(Self::Stderr),
            "prometheus" | "prom" => Some(Self::Prometheus),
            "otlp" | "otel" | "opentelemetry" => Some(Self::Otlp),
            "statsd" => Some(Self::Statsd),
            "cloudwatch" | "cw" => Some(Self::CloudWatch),
            _ => None,
        }
    }
}

/// Configuration for a single telemetry backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend type.
    pub kind: BackendKind,

    /// Endpoint URL (for OTLP, StatsD, CloudWatch).
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Output file path (for JSON file backend).
    #[serde(default)]
    pub path: Option<String>,

    /// Additional backend-specific settings.
    #[serde(default)]
    pub options: HashMap<String, String>,
}

/// Top-level telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Which audiences are active.
    #[serde(default)]
    pub audience: TelemetryAudience,

    /// Configured backends.
    #[serde(default = "default_backends")]
    pub backends: Vec<BackendConfig>,

    /// Fraction of runs that emit operator telemetry (0.0–1.0).
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: f64,

    /// How to decide whether to emit operator telemetry.
    #[serde(default)]
    pub sampling_strategy: SamplingStrategy,
}

fn default_sampling_rate() -> f64 {
    1.0
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            audience: TelemetryAudience::UserOnly,
            backends: default_backends(),
            sampling_rate: 1.0,
            sampling_strategy: SamplingStrategy::default(),
        }
    }
}

fn default_backends() -> Vec<BackendConfig> {
    vec![BackendConfig {
        kind: BackendKind::JsonFile,
        endpoint: None,
        path: Some("chaffra-telemetry.json".to_owned()),
        options: HashMap::new(),
    }]
}

impl TelemetryConfig {
    /// Build config from the `[modules.telemetry]` section of chaffra config.
    pub fn from_module_config(config: &HashMap<String, String>) -> Self {
        let audience = config
            .get("audience")
            .and_then(|v| TelemetryAudience::from_str_loose(v))
            .unwrap_or_default();

        let backend_kind = config
            .get("backend")
            .and_then(|v| BackendKind::from_str_loose(v));

        let endpoint = config.get("endpoint").cloned();
        let path = config.get("path").cloned();

        let backends = if let Some(kind) = backend_kind {
            vec![BackendConfig {
                kind,
                endpoint,
                path,
                options: HashMap::new(),
            }]
        } else {
            default_backends()
        };

        let sampling_rate = config
            .get("sampling-rate")
            .or_else(|| config.get("sampling_rate"))
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);

        let sampling_strategy = config
            .get("sampling-strategy")
            .or_else(|| config.get("sampling_strategy"))
            .and_then(|v| SamplingStrategy::from_str_loose(v))
            .unwrap_or_default();

        Self {
            audience,
            backends,
            sampling_rate,
            sampling_strategy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_default() {
        assert_eq!(TelemetryAudience::default(), TelemetryAudience::UserOnly);
    }

    #[test]
    fn test_audience_from_str() {
        assert_eq!(
            TelemetryAudience::from_str_loose("on"),
            Some(TelemetryAudience::On)
        );
        assert_eq!(
            TelemetryAudience::from_str_loose("off"),
            Some(TelemetryAudience::Off)
        );
        assert_eq!(
            TelemetryAudience::from_str_loose("user-only"),
            Some(TelemetryAudience::UserOnly)
        );
        assert_eq!(
            TelemetryAudience::from_str_loose("operator-only"),
            Some(TelemetryAudience::OperatorOnly)
        );
        assert_eq!(TelemetryAudience::from_str_loose("bogus"), None);
    }

    #[test]
    fn test_audience_flags() {
        assert!(TelemetryAudience::On.user_enabled());
        assert!(TelemetryAudience::On.operator_enabled());
        assert!(!TelemetryAudience::Off.user_enabled());
        assert!(!TelemetryAudience::Off.operator_enabled());
        assert!(TelemetryAudience::UserOnly.user_enabled());
        assert!(!TelemetryAudience::UserOnly.operator_enabled());
        assert!(!TelemetryAudience::OperatorOnly.user_enabled());
        assert!(TelemetryAudience::OperatorOnly.operator_enabled());
    }

    #[test]
    fn test_backend_kind_from_str() {
        assert_eq!(
            BackendKind::from_str_loose("json-file"),
            Some(BackendKind::JsonFile)
        );
        assert_eq!(
            BackendKind::from_str_loose("stderr"),
            Some(BackendKind::Stderr)
        );
        assert_eq!(
            BackendKind::from_str_loose("prometheus"),
            Some(BackendKind::Prometheus)
        );
        assert_eq!(BackendKind::from_str_loose("otlp"), Some(BackendKind::Otlp));
        assert_eq!(
            BackendKind::from_str_loose("statsd"),
            Some(BackendKind::Statsd)
        );
        assert_eq!(
            BackendKind::from_str_loose("cloudwatch"),
            Some(BackendKind::CloudWatch)
        );
        assert_eq!(BackendKind::from_str_loose("nope"), None);
    }

    #[test]
    fn test_default_config() {
        let cfg = TelemetryConfig::default();
        assert_eq!(cfg.audience, TelemetryAudience::UserOnly);
        assert_eq!(cfg.backends.len(), 1);
        assert_eq!(cfg.backends[0].kind, BackendKind::JsonFile);
        assert!((cfg.sampling_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(cfg.sampling_strategy, SamplingStrategy::Rate);
    }

    #[test]
    fn test_from_module_config() {
        let mut mc = HashMap::new();
        mc.insert("audience".to_owned(), "operator-only".to_owned());
        mc.insert("backend".to_owned(), "otlp".to_owned());
        mc.insert("endpoint".to_owned(), "http://localhost:4317".to_owned());

        let cfg = TelemetryConfig::from_module_config(&mc);
        assert_eq!(cfg.audience, TelemetryAudience::OperatorOnly);
        assert_eq!(cfg.backends.len(), 1);
        assert_eq!(cfg.backends[0].kind, BackendKind::Otlp);
        assert_eq!(
            cfg.backends[0].endpoint.as_deref(),
            Some("http://localhost:4317")
        );
    }

    #[test]
    fn test_from_module_config_defaults() {
        let mc = HashMap::new();
        let cfg = TelemetryConfig::from_module_config(&mc);
        assert_eq!(cfg.audience, TelemetryAudience::UserOnly);
        assert_eq!(cfg.backends[0].kind, BackendKind::JsonFile);
        assert!((cfg.sampling_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(cfg.sampling_strategy, SamplingStrategy::Rate);
    }

    #[test]
    fn test_from_module_config_sampling() {
        let mut mc = HashMap::new();
        mc.insert("sampling-rate".to_owned(), "0.5".to_owned());
        mc.insert("sampling-strategy".to_owned(), "on-change".to_owned());
        let cfg = TelemetryConfig::from_module_config(&mc);
        assert!((cfg.sampling_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(cfg.sampling_strategy, SamplingStrategy::OnChange);
    }

    #[test]
    fn test_sampling_rate_clamped() {
        let mut mc = HashMap::new();
        mc.insert("sampling-rate".to_owned(), "5.0".to_owned());
        let cfg = TelemetryConfig::from_module_config(&mc);
        assert!((cfg.sampling_rate - 1.0).abs() < f64::EPSILON);

        mc.insert("sampling-rate".to_owned(), "-1.0".to_owned());
        let cfg = TelemetryConfig::from_module_config(&mc);
        assert!((cfg.sampling_rate - 0.0).abs() < f64::EPSILON);
    }
}
