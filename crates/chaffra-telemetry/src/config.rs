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
    ///
    /// Returns an error if `audience` is present but not a recognized value.
    pub fn from_module_config(config: &HashMap<String, String>) -> Result<Self, String> {
        let audience = match config.get("audience") {
            Some(v) => TelemetryAudience::from_str_loose(v).ok_or_else(|| {
                format!(
                    "invalid [modules.telemetry] audience: {v:?}; \
                     valid values: on, off, user-only, operator-only"
                )
            })?,
            None => TelemetryAudience::default(),
        };

        let backend_kind = match config.get("backend") {
            Some(v) => Some(BackendKind::from_str_loose(v).ok_or_else(|| {
                format!(
                    "invalid [modules.telemetry] backend: {v:?}; \
                     valid values: json-file, stderr, prometheus, otlp, statsd, cloudwatch"
                )
            })?),
            None => None,
        };

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

        let sampling_rate = match config
            .get("sampling-rate")
            .or_else(|| config.get("sampling_rate"))
        {
            Some(v) => v
                .parse::<f64>()
                .map_err(|_| {
                    format!(
                        "invalid [modules.telemetry] sampling-rate: {v:?}; \
                     expected a number between 0.0 and 1.0"
                    )
                })?
                .clamp(0.0, 1.0),
            None => 1.0,
        };

        let sampling_strategy = match config
            .get("sampling-strategy")
            .or_else(|| config.get("sampling_strategy"))
        {
            Some(v) => SamplingStrategy::from_str_loose(v).ok_or_else(|| {
                format!(
                    "invalid [modules.telemetry] sampling-strategy: {v:?}; \
                     valid values: rate, on-change"
                )
            })?,
            None => SamplingStrategy::default(),
        };

        Ok(Self {
            audience,
            backends,
            sampling_rate,
            sampling_strategy,
        })
    }

    /// Merge project-level `[modules.telemetry]` config into a base config.
    ///
    /// Fails closed: invalid project config is an error, not a silent fallback.
    /// When `explicit_base_audience` is true, the base audience takes priority
    /// over the project config (used when the CLI `--telemetry` flag was set).
    pub fn merge_project_config(
        &self,
        project_config: &HashMap<String, String>,
        explicit_base_audience: bool,
    ) -> Result<Self, String> {
        let project_tel = Self::from_module_config(project_config)?;
        let mut merged = self.clone();
        merged.sampling_rate = project_tel.sampling_rate;
        merged.sampling_strategy = project_tel.sampling_strategy;

        if !explicit_base_audience {
            merged.audience = project_tel.audience;
        }

        let base_is_default_backends = merged.backends.len() == 1
            && merged.backends[0].kind == BackendKind::JsonFile
            && merged.backends[0].path.as_deref() == Some("chaffra-telemetry.json");
        if base_is_default_backends && !project_tel.backends.is_empty() {
            let proj_is_default = project_tel.backends.len() == 1
                && project_tel.backends[0].kind == BackendKind::JsonFile
                && project_tel.backends[0].path.as_deref() == Some("chaffra-telemetry.json");
            if !proj_is_default {
                merged.backends = project_tel.backends;
            }
        }
        Ok(merged)
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

        let cfg = TelemetryConfig::from_module_config(&mc).unwrap();
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
        let cfg = TelemetryConfig::from_module_config(&mc).unwrap();
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
        let cfg = TelemetryConfig::from_module_config(&mc).unwrap();
        assert!((cfg.sampling_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(cfg.sampling_strategy, SamplingStrategy::OnChange);
    }

    #[test]
    fn test_sampling_rate_clamped() {
        let mut mc = HashMap::new();
        mc.insert("sampling-rate".to_owned(), "5.0".to_owned());
        let cfg = TelemetryConfig::from_module_config(&mc).unwrap();
        assert!((cfg.sampling_rate - 1.0).abs() < f64::EPSILON);

        mc.insert("sampling-rate".to_owned(), "-1.0".to_owned());
        let cfg = TelemetryConfig::from_module_config(&mc).unwrap();
        assert!((cfg.sampling_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_from_module_config_invalid_backend_fails() {
        let mut mc = HashMap::new();
        mc.insert("backend".to_owned(), "bogus-sink".to_owned());
        let result = TelemetryConfig::from_module_config(&mc);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid"));
    }

    #[test]
    fn test_from_module_config_invalid_sampling_rate_fails() {
        let mut mc = HashMap::new();
        mc.insert("sampling-rate".to_owned(), "not-a-number".to_owned());
        let result = TelemetryConfig::from_module_config(&mc);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sampling-rate"));
    }

    #[test]
    fn test_from_module_config_invalid_sampling_strategy_fails() {
        let mut mc = HashMap::new();
        mc.insert("sampling-strategy".to_owned(), "bogus".to_owned());
        let result = TelemetryConfig::from_module_config(&mc);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("sampling-strategy"));
    }

    #[test]
    fn test_merge_project_config_propagates_audience() {
        let base = TelemetryConfig::default();
        let mut mc = HashMap::new();
        mc.insert("audience".to_owned(), "on".to_owned());
        let merged = base.merge_project_config(&mc, false).unwrap();
        assert_eq!(merged.audience, TelemetryAudience::On);
    }

    #[test]
    fn test_merge_project_config_explicit_base_wins() {
        let base = TelemetryConfig::default();
        let mut mc = HashMap::new();
        mc.insert("audience".to_owned(), "on".to_owned());
        let merged = base.merge_project_config(&mc, true).unwrap();
        assert_eq!(merged.audience, TelemetryAudience::UserOnly);
    }

    #[test]
    fn test_merge_project_config_fails_on_invalid() {
        let base = TelemetryConfig::default();
        let mut mc = HashMap::new();
        mc.insert("audience".to_owned(), "bogus".to_owned());
        assert!(base.merge_project_config(&mc, false).is_err());
    }

    #[test]
    fn test_merge_project_config_merges_backends() {
        let base = TelemetryConfig::default();
        let mut mc = HashMap::new();
        mc.insert("backend".to_owned(), "otlp".to_owned());
        mc.insert("endpoint".to_owned(), "http://localhost:4317".to_owned());
        let merged = base.merge_project_config(&mc, false).unwrap();
        assert_eq!(merged.backends[0].kind, BackendKind::Otlp);
    }

    #[test]
    fn test_merge_project_config_merges_sampling() {
        let base = TelemetryConfig::default();
        let mut mc = HashMap::new();
        mc.insert("sampling-rate".to_owned(), "0.25".to_owned());
        mc.insert("sampling-strategy".to_owned(), "on-change".to_owned());
        let merged = base.merge_project_config(&mc, false).unwrap();
        assert!((merged.sampling_rate - 0.25).abs() < f64::EPSILON);
        assert_eq!(merged.sampling_strategy, SamplingStrategy::OnChange);
    }
}
