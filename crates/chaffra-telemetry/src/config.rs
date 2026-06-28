//! Telemetry configuration types.
//!
//! Maps to the `[modules.telemetry]` section in `.chaffra.toml`.

use crate::error::TelemetryError;
use crate::sampling::SamplingStrategy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Which telemetry audiences are enabled.
///
/// The default is [`TelemetryAudience::UserOnly`] (Phase 15a.1): a default
/// invocation collects user-facing summary metrics only and CANNOT emit
/// operator metrics — those carry process- and environment-shaped data that
/// is treated as personal/operational under GDPR data-minimisation, so it
/// must be opted into explicitly via `--telemetry on|operator-only` or the
/// `[modules.telemetry] audience` file setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TelemetryAudience {
    /// Both user-facing and operator metrics.
    On,
    /// All telemetry disabled.
    Off,
    /// Only user-facing metrics (finding counts, durations in output).
    ///
    /// This is the default: operator metrics are never produced unless the
    /// operator audience is explicitly requested.
    #[default]
    UserOnly,
    /// Only operator metrics (backend sinks, no output decoration).
    OperatorOnly,
}

impl TelemetryAudience {
    /// Parse from a CLI flag value, failing closed on an unknown value.
    ///
    /// Unlike [`from_str_loose`](Self::from_str_loose), an unrecognised value
    /// is a typed error rather than `None`, so callers never silently coerce a
    /// typo (`--telemetry oprator-only`) into a default that emits more than
    /// the user asked for.
    pub fn parse(s: &str) -> Result<Self, TelemetryError> {
        Self::from_str_loose(s).ok_or_else(|| TelemetryError::InvalidAudience(s.to_owned()))
    }

    /// Parse from a CLI flag / file value, returning `None` on an unknown value.
    ///
    /// Only the four documented audience modes (plus snake_case spellings) are
    /// accepted. Boolean/integer-style aliases (`true`/`1`/`false`/`0`) are
    /// intentionally NOT accepted (R9-F3): `ChaffraConfig::module_config`
    /// stringifies non-string TOML, so accepting `"true"`/`"1"` would let a
    /// checked-in `[modules.telemetry] audience = true` (a TOML boolean) silently
    /// become an operator opt-in. Rejecting them makes any non-string / non-mode
    /// value fail closed through `parse`.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
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
    /// Parse from a CLI/file value, failing closed on an unknown value.
    ///
    /// Mirrors [`TelemetryAudience::parse`]: a present-but-unrecognised backend
    /// is a typed error rather than `None`, so neither the file
    /// (`[modules.telemetry] backend`) nor the CLI (`--telemetry-backend`) path
    /// can silently coerce a typo (`otlpz`) into the default JSON-file backend.
    pub fn parse(s: &str) -> Result<Self, TelemetryError> {
        Self::from_str_loose(s).ok_or_else(|| {
            TelemetryError::InvalidBackendConfig(format!(
                "unknown backend {s:?} (expected one of: json-file, stderr, prometheus, otlp, statsd, cloudwatch)"
            ))
        })
    }

    /// Parse from a CLI flag value, returning `None` on an unknown value.
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

    /// An explicit CLI `--telemetry` audience, if one was passed.
    ///
    /// This is a precedence hint, not persisted state: it records whether the
    /// audience in [`audience`](Self::audience) came from an explicit command
    /// line flag (`Some`) or merely the default/file value (`None`), so the
    /// config-merge step can let an explicit flag win over a checked-in
    /// `[modules.telemetry] audience`. It never crosses a wire or disk boundary
    /// — `#[serde(skip)]` keeps it out of every serialized snapshot and backend
    /// payload, so the persisted telemetry schema is unchanged.
    #[serde(skip)]
    pub cli_audience_override: Option<TelemetryAudience>,

    /// The global `--config <file>` path, if one was passed at the CLI.
    ///
    /// Carries the explicit project config path from the CLI dispatch down to
    /// the telemetry diagnostic subcommands (`status` / `test` / `inspect`),
    /// which need to honour the same `.chaffra.toml` a live run would use.
    /// Threading it as a separate argument forced a signature change at the
    /// `main()` dispatch site — same pattern as
    /// [`cli_audience_override`](Self::cli_audience_override): a precedence
    /// hint that lives on the telemetry-config carrier so the per-arm
    /// dispatch in `main()` stays a one-line `print!` and does not need to
    /// learn about CLI fields. `#[serde(skip)]` keeps it out of every
    /// serialized snapshot and backend payload.
    #[serde(skip)]
    pub cli_config_path: Option<String>,
}

fn default_sampling_rate() -> f64 {
    1.0
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            audience: TelemetryAudience::default(),
            backends: default_backends(),
            sampling_rate: 1.0,
            sampling_strategy: SamplingStrategy::default(),
            cli_audience_override: None,
            cli_config_path: None,
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
    /// Fails closed: a `backend`, `audience`, `sampling-rate`, or
    /// `sampling-strategy` key with an unrecognised value is a typed error,
    /// never coerced to the default (a valid-but-out-of-range `sampling-rate`
    /// is clamped, which is range normalisation, not a swallowed parse failure;
    /// a non-finite `sampling-rate` is rejected). An ABSENT key defaults. This
    /// is the single config-loading path shared by the CLI and the telemetry
    /// module — there is no lenient alternate path that would let a malformed
    /// value silently take effect.
    pub fn from_module_config(config: &HashMap<String, String>) -> Result<Self, TelemetryError> {
        let audience = match config.get("audience") {
            Some(v) => TelemetryAudience::parse(v)?,
            None => TelemetryAudience::default(),
        };

        let endpoint = config.get("endpoint").cloned();
        let path = config.get("path").cloned();

        // Fail closed on a present-but-invalid `backend` (mirroring `audience`):
        // an unrecognised value is a typed error, never silently coerced to the
        // default JSON-file backend. An ABSENT key still uses `default_backends`.
        let backends = match config.get("backend") {
            Some(v) => vec![BackendConfig {
                kind: BackendKind::parse(v)?,
                endpoint,
                path,
                options: HashMap::new(),
            }],
            None => default_backends(),
        };

        // Fail closed on a present-but-invalid value (mirroring `audience`):
        // a non-numeric `sampling-rate` is a typed error, never silently
        // coerced to the default. An ABSENT key still defaults to 1.0. A
        // valid-but-out-of-range number is normalised by `clamp` (an explicit,
        // tested behaviour — see `test_sampling_rate_clamped` — not a swallowed
        // parse failure).
        //
        // EVERY present spelling is validated (R9-F4): a present-but-invalid
        // alternate spelling must fail closed even when the preferred spelling
        // is valid, so the short-circuiting `get(...).or_else(get(...))` is
        // replaced by a loop over both spellings. Iterate snake-case first so
        // the canonical kebab-case spelling wins when both are present + valid.
        let mut sampling_rate = 1.0;
        for key in ["sampling_rate", "sampling-rate"] {
            if let Some(v) = config.get(key) {
                let parsed = v.parse::<f64>().map_err(|_| {
                    TelemetryError::InvalidSamplingConfig(format!(
                        "invalid {key} {v:?} (expected a number in [0.0, 1.0])"
                    ))
                })?;
                // `f64::parse` accepts `NaN` / `inf` / `-inf`, and `clamp`
                // preserves `NaN` — reject non-finite values rather than carry
                // an undefined rate into sampling decisions.
                if !parsed.is_finite() {
                    return Err(TelemetryError::InvalidSamplingConfig(format!(
                        "non-finite {key} {v:?} (expected a finite number in [0.0, 1.0])"
                    )));
                }
                sampling_rate = parsed.clamp(0.0, 1.0);
            }
        }

        // Same fail-closed, validate-every-spelling contract for
        // `sampling-strategy`.
        let mut sampling_strategy = SamplingStrategy::default();
        for key in ["sampling_strategy", "sampling-strategy"] {
            if let Some(v) = config.get(key) {
                sampling_strategy = SamplingStrategy::from_str_loose(v).ok_or_else(|| {
                    TelemetryError::InvalidSamplingConfig(format!(
                        "invalid {key} {v:?} (expected one of: rate, on-change)"
                    ))
                })?;
            }
        }

        Ok(Self {
            audience,
            backends,
            sampling_rate,
            sampling_strategy,
            cli_audience_override: None,
            cli_config_path: None,
        })
    }

    /// Resolve the effective audience for a run, applying the precedence:
    /// explicit CLI `--telemetry` flag > file `[modules.telemetry] audience` >
    /// `base` (the CLI-derived base, which is itself the flag value or the
    /// `user-only` default).
    ///
    /// `cli_audience` is the parsed CLI flag (`None` when the flag was omitted);
    /// `file_audience` is the audience parsed from the project file's telemetry
    /// section, present only when the file explicitly set `audience`; `base` is
    /// the fallback used when neither explicit source applies. An explicit CLI
    /// flag is authoritative — a checked-in file can never re-enable operator
    /// emission that the operator disabled on the command line (e.g.
    /// `--telemetry off`), and can never override a narrower explicit
    /// `--telemetry user-only`. This is the single precedence rule; both the CLI
    /// and the telemetry module resolve through it.
    #[must_use]
    pub fn resolve_audience(
        cli_audience: Option<TelemetryAudience>,
        file_audience: Option<TelemetryAudience>,
        base: TelemetryAudience,
    ) -> TelemetryAudience {
        cli_audience.or(file_audience).unwrap_or(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audience_default_is_user_only() {
        // Phase 15a.1: the default audience must NOT enable operator emission.
        assert_eq!(TelemetryAudience::default(), TelemetryAudience::UserOnly);
        assert!(TelemetryAudience::default().user_enabled());
        assert!(!TelemetryAudience::default().operator_enabled());
    }

    #[test]
    fn test_audience_parse_valid() {
        assert_eq!(
            TelemetryAudience::parse("on").unwrap(),
            TelemetryAudience::On
        );
        assert_eq!(
            TelemetryAudience::parse("operator-only").unwrap(),
            TelemetryAudience::OperatorOnly
        );
    }

    #[test]
    fn test_audience_parse_invalid_fails_closed() {
        let err = TelemetryAudience::parse("oprator-only").unwrap_err();
        assert!(
            matches!(err, TelemetryError::InvalidAudience(ref v) if v == "oprator-only"),
            "got: {err:?}"
        );
        // The actionable message must name the accepted values.
        let msg = TelemetryAudience::parse("bogus").unwrap_err().to_string();
        assert!(msg.contains("operator-only"), "message was: {msg}");
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
        // R9-F3: boolean/integer-style aliases are NOT accepted, so a
        // stringified non-string TOML `audience` value fails closed.
        for rejected in ["true", "1", "false", "0"] {
            assert_eq!(
                TelemetryAudience::from_str_loose(rejected),
                None,
                "alias {rejected} must not be accepted as an audience mode"
            );
        }
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
        assert!(!cfg.audience.operator_enabled());
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
        // No `audience` key -> the privacy-preserving default.
        assert_eq!(cfg.audience, TelemetryAudience::UserOnly);
        assert!(!cfg.audience.operator_enabled());
        assert_eq!(cfg.backends[0].kind, BackendKind::JsonFile);
        assert!((cfg.sampling_rate - 1.0).abs() < f64::EPSILON);
        assert_eq!(cfg.sampling_strategy, SamplingStrategy::Rate);
    }

    #[test]
    fn test_from_module_config_invalid_audience_fails_closed() {
        let mut mc = HashMap::new();
        mc.insert("audience".to_owned(), "everyone".to_owned());
        let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
        assert!(matches!(err, TelemetryError::InvalidAudience(v) if v == "everyone"));
    }

    #[test]
    fn test_from_module_config_invalid_sampling_rate_fails_closed() {
        // A present-but-unparseable `sampling-rate` is a typed error, never
        // silently coerced to the 1.0 default (mirrors the `audience` contract).
        for spelling in ["sampling-rate", "sampling_rate"] {
            let mut mc = HashMap::new();
            mc.insert(spelling.to_owned(), "banana".to_owned());
            let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
            assert!(
                matches!(err, TelemetryError::InvalidSamplingConfig(ref v) if v.contains("banana")),
                "spelling={spelling}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_from_module_config_invalid_sampling_strategy_fails_closed() {
        // Same fail-closed contract for `sampling-strategy`.
        for spelling in ["sampling-strategy", "sampling_strategy"] {
            let mut mc = HashMap::new();
            mc.insert(spelling.to_owned(), "bogus".to_owned());
            let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
            assert!(
                matches!(err, TelemetryError::InvalidSamplingConfig(ref v) if v.contains("bogus")),
                "spelling={spelling}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_from_module_config_non_string_audience_fails_closed() {
        // R9-F3: `ChaffraConfig::module_config` stringifies non-string TOML, so
        // `audience = true` / `audience = 1` arrive here as "true" / "1". These
        // are NOT documented modes and must fail closed — never silently become
        // an operator opt-in (`On`).
        for value in ["true", "1", "false", "0"] {
            let mut mc = HashMap::new();
            mc.insert("audience".to_owned(), value.to_owned());
            let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
            assert!(
                matches!(err, TelemetryError::InvalidAudience(ref v) if v == value),
                "audience={value} must fail closed, got {err:?}"
            );
        }
    }

    #[test]
    fn test_from_module_config_invalid_duplicate_sampling_spelling_fails_closed() {
        // R9-F4: when both spellings are present, a present-but-invalid
        // alternate spelling must fail closed even though the preferred spelling
        // is valid (the old `get().or_else(get())` short-circuited past it).
        let mut mc = HashMap::new();
        mc.insert("sampling-rate".to_owned(), "0.5".to_owned()); // valid
        mc.insert("sampling_rate".to_owned(), "banana".to_owned()); // invalid
        let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
        assert!(
            matches!(err, TelemetryError::InvalidSamplingConfig(ref v) if v.contains("banana")),
            "present invalid sampling_rate alias must fail closed, got {err:?}"
        );

        let mut mc = HashMap::new();
        mc.insert("sampling-strategy".to_owned(), "rate".to_owned()); // valid
        mc.insert("sampling_strategy".to_owned(), "bogus".to_owned()); // invalid
        let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
        assert!(
            matches!(err, TelemetryError::InvalidSamplingConfig(ref v) if v.contains("bogus")),
            "present invalid sampling_strategy alias must fail closed, got {err:?}"
        );
    }

    #[test]
    fn test_from_module_config_invalid_backend_fails_closed() {
        // A present-but-unrecognised `backend` is a typed error, never silently
        // coerced to the default JSON-file backend.
        let mut mc = HashMap::new();
        mc.insert("backend".to_owned(), "otlpz".to_owned());
        let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
        assert!(
            matches!(err, TelemetryError::InvalidBackendConfig(ref v) if v.contains("otlpz")),
            "got {err:?}"
        );
    }

    #[test]
    fn test_from_module_config_non_finite_sampling_rate_fails_closed() {
        // `f64::parse` accepts NaN/inf/-inf; these are present-but-invalid and
        // must fail closed rather than carry a non-finite rate into sampling.
        for value in ["NaN", "nan", "inf", "-inf", "infinity"] {
            let mut mc = HashMap::new();
            mc.insert("sampling-rate".to_owned(), value.to_owned());
            let err = TelemetryConfig::from_module_config(&mc).unwrap_err();
            assert!(
                matches!(err, TelemetryError::InvalidSamplingConfig(ref v) if v.contains("non-finite")),
                "value={value}, got {err:?}"
            );
        }
    }

    #[test]
    fn test_from_module_config_each_audience() {
        for (value, expected) in [
            ("on", TelemetryAudience::On),
            ("off", TelemetryAudience::Off),
            ("user-only", TelemetryAudience::UserOnly),
            ("operator-only", TelemetryAudience::OperatorOnly),
        ] {
            let mut mc = HashMap::new();
            mc.insert("audience".to_owned(), value.to_owned());
            let cfg = TelemetryConfig::from_module_config(&mc).unwrap();
            assert_eq!(cfg.audience, expected, "audience={value}");
        }
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
    fn test_cli_audience_override_defaults_to_none() {
        // The precedence hint is absent on both the default config and any
        // config loaded from a file section; it is only ever set by the CLI.
        assert_eq!(TelemetryConfig::default().cli_audience_override, None);
        let mut mc = HashMap::new();
        mc.insert("audience".to_owned(), "on".to_owned());
        assert_eq!(
            TelemetryConfig::from_module_config(&mc)
                .unwrap()
                .cli_audience_override,
            None
        );
    }

    #[test]
    fn test_cli_audience_override_is_not_serialized() {
        // `#[serde(skip)]`: the precedence hint must never reach the persisted
        // schema, and a deserialized config defaults it back to `None`.
        let mut cfg = TelemetryConfig::default();
        cfg.cli_audience_override = Some(TelemetryAudience::Off);
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            !json.contains("cli_audience_override"),
            "precedence hint leaked into serialized config: {json}"
        );
        let restored: TelemetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.cli_audience_override, None);
    }

    #[test]
    fn test_resolve_audience_precedence() {
        use TelemetryAudience::{Off, On, OperatorOnly, UserOnly};
        // (cli, file, base, expected) — explicit CLI flag wins over file, file
        // wins over the base fallback.
        let cases = [
            // Explicit CLI beats file in BOTH directions.
            (Some(Off), Some(On), UserOnly, Off),
            (Some(On), Some(Off), UserOnly, On),
            (Some(UserOnly), Some(On), UserOnly, UserOnly),
            (Some(OperatorOnly), Some(UserOnly), UserOnly, OperatorOnly),
            // `--telemetry off` is not overridable by a checked-in file.
            (Some(Off), Some(OperatorOnly), UserOnly, Off),
            // No CLI flag: the file governs when present (over the base).
            (None, Some(On), UserOnly, On),
            (None, Some(OperatorOnly), UserOnly, OperatorOnly),
            // Neither explicit source: the base fallback applies.
            (None, None, UserOnly, UserOnly),
            (None, None, On, On),
        ];
        for (cli, file, base, expected) in cases {
            assert_eq!(
                TelemetryConfig::resolve_audience(cli, file, base),
                expected,
                "cli={cli:?} file={file:?} base={base:?}"
            );
        }
    }
}
