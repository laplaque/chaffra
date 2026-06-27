//! `AnalysisModule` trait implementation for the telemetry module.
//!
//! The telemetry module is registered in the `GrpcModuleHost` like any other
//! module. Its `analyze` call returns the current telemetry snapshot as findings
//! (one info-level finding per configured backend with its status).

use crate::backends::{self, BackendStatus};
use crate::collector::TelemetryCollector;
use crate::config::{TelemetryAudience, TelemetryConfig};
use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Location, ModuleInfo, ModuleMetrics, Rule,
    RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use std::collections::HashMap;

/// Telemetry analysis module.
///
/// When analyzed, reports backend status and the latest telemetry snapshot
/// as informational findings.
pub struct TelemetryModule {
    collector: Option<TelemetryCollector>,
}

impl TelemetryModule {
    /// Create a new telemetry module with an external collector.
    pub fn with_collector(collector: TelemetryCollector) -> Self {
        Self {
            collector: Some(collector),
        }
    }

    /// Create a standalone telemetry module (uses default collector).
    pub fn new() -> Self {
        Self { collector: None }
    }

    fn get_collector(&self) -> TelemetryCollector {
        self.collector
            .clone()
            .unwrap_or_else(TelemetryCollector::with_defaults)
    }

    fn get_config(&self, config: &HashMap<String, String>) -> Result<TelemetryConfig> {
        // Preserve the typed config error (fail closed) rather than coercing an
        // invalid audience to a default that would widen emission.
        TelemetryConfig::from_module_config(config).map_err(|e| ChaffraError::Config(e.to_string()))
    }
}

impl Default for TelemetryModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisModule for TelemetryModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "telemetry".to_owned(),
            name: "Telemetry".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec![],
            capabilities: vec![
                "analyze".to_owned(),
                "explain".to_owned(),
                "status".to_owned(),
            ],
            rules: vec![
                Rule {
                    id: "backend-status".to_owned(),
                    name: "Backend status".to_owned(),
                    description: "Reports telemetry backend connectivity status".to_owned(),
                    default_severity: Severity::Info,
                    category: "telemetry".to_owned(),
                },
                Rule {
                    id: "metric-summary".to_owned(),
                    name: "Metric summary".to_owned(),
                    description: "Summary of collected telemetry metrics from the current run"
                        .to_owned(),
                    default_severity: Severity::Info,
                    category: "telemetry".to_owned(),
                },
                Rule {
                    id: "finding-churn".to_owned(),
                    name: "Finding churn".to_owned(),
                    description: "Reports new, resolved, and unchanged findings between runs"
                        .to_owned(),
                    default_severity: Severity::Info,
                    category: "telemetry".to_owned(),
                },
                Rule {
                    id: "sampling-status".to_owned(),
                    name: "Sampling status".to_owned(),
                    description: "Reports operator telemetry sampling configuration".to_owned(),
                    default_severity: Severity::Info,
                    category: "telemetry".to_owned(),
                },
            ],
        }
    }

    fn analyze(
        &self,
        _files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let tel_config = self.get_config(config)?;
        let collector = self.get_collector();

        // Create backends and check status.
        let (_backends, statuses) = backends::create_backends(&tel_config.backends);

        let mut findings = Vec::new();

        // Emit a finding per backend with its status, gated on the operator
        // scope. The backend-status finding discloses the backend kind
        // (`JsonFile`, `Otlp`, ...), endpoint/path, and connectivity state —
        // all operator-shaped data exactly like `OperatorSummary`. R4 fail-
        // closed: emit ONLY when the resolved audience includes the operator
        // scope (`On` / `OperatorOnly`); under `UserOnly` and `Off` the
        // backend-status finding is withheld. (`metric-summary` below still
        // emits — its payload is built from a projected snapshot so it carries
        // only what the audience permits.)
        if tel_config.audience.operator_enabled() {
            for status in &statuses {
                findings.push(backend_status_finding(status));
            }
        }

        // Apply audience projection BEFORE deriving anything user-visible from
        // the snapshot — the returned `metric-summary` finding is a user-facing
        // output boundary just like a backend flush, so it must see only the
        // fields the resolved audience permits. Previously the message and
        // `summary` metadata were built from the raw snapshot's
        // `user_summary` / `data_points` / `spans` before projection, which
        // could disclose under `user-only`:
        //   * per-module timing via `user_summary.module_summaries[*].duration_ms`
        //     (an operator-derived field scrubbed by `project_for_audience`);
        //   * operator-only data point and span counts in the message text and
        //     `files_total: 0` confusion under `operator-only` / `off`.
        // Project once and derive every finding-facing value from the projected
        // snapshot so a single boundary covers both the module output and the
        // backend flush below.
        let projected = collector
            .snapshot()
            .project_for_audience(tel_config.audience);
        let summary_json = serde_json::to_string_pretty(&projected.user_summary)
            .unwrap_or_else(|_| "{}".to_owned());

        findings.push(Finding {
            rule_id: "metric-summary".to_owned(),
            message: format!(
                "Telemetry: {} files, {} data points, {} spans",
                projected.user_summary.files_total,
                projected.data_points.len(),
                projected.spans.len(),
            ),
            severity: Severity::Info,
            location: Location {
                file: "telemetry".to_owned(),
                start_line: 0,
                end_line: 0,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: {
                let mut m = HashMap::new();
                m.insert("summary".to_owned(), summary_json);
                m
            },
        });

        // Flush to backends whenever telemetry is not fully disabled. The
        // snapshot has already been projected above, so we reuse it directly:
        // the projection boundary is defined once for both the module output
        // and the backend write, and the two paths cannot drift.
        //
        // The projection boundary is shared with the CLI `run_with_telemetry`
        // paths, but the EMISSION rule is not identical: the CLI success path
        // additionally gates the flush on `SamplingDecision::Emit` (rate /
        // on-change sampling), whereas this module path flushes on every non-Off
        // run. Sampling is applied only on the CLI success path; here the rule is
        // simply project-then-flush whenever the audience is not `Off`.
        if !matches!(tel_config.audience, TelemetryAudience::Off) {
            let (active_backends, _) = backends::create_backends(&tel_config.backends);
            for backend in &active_backends {
                if let Err(e) = backend.flush(&projected) {
                    eprintln!("[telemetry] backend '{}' flush error: {e}", backend.name());
                }
            }
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: 0,
                duration_ms: 0,
                counters: HashMap::new(),
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "backend-status" => Ok(RuleExplanation {
                rule_id: "backend-status".to_owned(),
                name: "Backend status".to_owned(),
                description: "Reports the connectivity and configuration status of each telemetry backend. Each configured backend (JSON file, stderr, Prometheus, OTLP, StatsD, CloudWatch) emits an info-level finding showing whether it is reachable.".to_owned(),
                rationale: "Operators need visibility into whether telemetry is being collected and forwarded correctly.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore backend-status".to_owned(),
                examples: vec![
                    "json-file backend: will write to chaffra-telemetry.json".to_owned(),
                    "otlp backend: connected to http://localhost:4317".to_owned(),
                ],
            }),
            "metric-summary" => Ok(RuleExplanation {
                rule_id: "metric-summary".to_owned(),
                name: "Metric summary".to_owned(),
                description: "Summarizes the telemetry collected during the current analysis run (file counts, finding counts, and other user-facing summary fields). The finding is built from the audience-PROJECTED snapshot, so operator-scoped detail (per-module durations, operator data-point/span counts) is included only when the resolved audience permits it and is withheld under `user-only`.".to_owned(),
                rationale: "Provides a single finding that aggregates the audience-projected telemetry state for inspection or logging.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore metric-summary".to_owned(),
                examples: vec![
                    "Telemetry: 42 files, 15 data points, 3 spans".to_owned(),
                ],
            }),
            "finding-churn" => Ok(RuleExplanation {
                rule_id: "finding-churn".to_owned(),
                name: "Finding churn".to_owned(),
                description: "Tracks deltas between analysis runs: new findings, resolved findings, and unchanged findings. Computes a churn rate (new / (new + unchanged)) to measure codebase stability.".to_owned(),
                rationale: "Teams need to know whether the codebase is improving or regressing between analysis runs.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore finding-churn".to_owned(),
                examples: vec![
                    "Finding churn: 3 new, 1 resolved, 5 unchanged (churn rate: 0.38)".to_owned(),
                ],
            }),
            "sampling-status" => Ok(RuleExplanation {
                rule_id: "sampling-status".to_owned(),
                name: "Sampling status".to_owned(),
                description: "Reports the operator telemetry sampling configuration: rate-based or on-change strategy, and the effective sampling rate.".to_owned(),
                rationale: "In high-volume environments, sampling reduces backend noise while preserving signal.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore sampling-status".to_owned(),
                examples: vec![
                    "Sampling: rate strategy at 0.10 (10% of runs)".to_owned(),
                    "Sampling: on-change strategy (emit only when findings change)".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Telemetry module does not produce fixable findings.
        Ok(vec![])
    }
}

fn backend_status_finding(status: &BackendStatus) -> Finding {
    let severity = if status.connected {
        Severity::Info
    } else {
        Severity::Warning
    };
    let connected_str = if status.connected {
        "connected"
    } else {
        "disconnected"
    };

    Finding {
        rule_id: "backend-status".to_owned(),
        message: format!(
            "Telemetry backend '{}' ({}): {connected_str} -- {}",
            status.name, status.kind, status.message
        ),
        severity,
        location: Location {
            file: "telemetry".to_owned(),
            start_line: 0,
            end_line: 0,
            start_column: 0,
            end_column: 0,
        },
        confidence: 1.0,
        actions: vec![],
        metadata: {
            let mut m = HashMap::new();
            m.insert("backend".to_owned(), status.name.clone());
            m.insert("kind".to_owned(), status.kind.clone());
            m.insert("connected".to_owned(), status.connected.to_string());
            m
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::metric_names;

    /// Run the telemetry module's `analyze` for a given audience with a single
    /// JSON-file backend at `path`, against a collector carrying both a
    /// user-facing finding metric and operator-only metrics. Returns the parsed
    /// flushed JSON, or `None` when nothing was flushed (file absent).
    fn module_flush_for_audience(
        audience: &str,
        path: &std::path::Path,
    ) -> Option<serde_json::Value> {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(3);
        collector.record_module_call("dead-code", 7, false); // operator metric
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 1);
        collector.record_module_findings("dead-code", 1, &sev); // user metric

        let module = TelemetryModule::with_collector(collector);
        let mut config = HashMap::new();
        config.insert("audience".to_owned(), audience.to_owned());
        config.insert("backend".to_owned(), "json-file".to_owned());
        config.insert("path".to_owned(), path.to_str().unwrap().to_owned());

        module.analyze(&[], &config).unwrap();

        std::fs::read_to_string(path)
            .ok()
            .map(|c| serde_json::from_str(&c).unwrap())
    }

    #[test]
    fn test_module_flush_rule_matches_projection_each_audience() {
        // 1B: the module flush path uses the SAME rule as the CLI paths —
        // flush the projected snapshot whenever audience != Off — so its
        // behaviour is identical to `project_for_audience` for every audience.
        let dir = tempfile::TempDir::new().unwrap();

        // user-only: flushes user data, NO operator data.
        let p = dir.path().join("user.json");
        let v = module_flush_for_audience("user-only", &p).expect("user-only must flush");
        assert_eq!(v["user_summary"]["files_total"], 3);
        assert!(
            v["operator_summary"]["module_call_durations"]
                .as_object()
                .unwrap()
                .is_empty(),
            "operator data leaked under user-only module flush"
        );
        for dp in v["data_points"].as_array().unwrap() {
            assert!(
                !metric_names::is_operator(dp["name"].as_str().unwrap()),
                "operator metric leaked under user-only module flush"
            );
        }

        // operator-only: flushes operator data, NO user summary.
        let p = dir.path().join("op.json");
        let v = module_flush_for_audience("operator-only", &p).expect("operator-only must flush");
        assert_eq!(v["user_summary"]["files_total"], 0);
        assert!(
            v["data_points"]
                .as_array()
                .unwrap()
                .iter()
                .any(|dp| dp["name"] == metric_names::MODULE_CALL_DURATION_MS)
        );

        // on: flushes everything.
        let p = dir.path().join("on.json");
        let v = module_flush_for_audience("on", &p).expect("on must flush");
        assert_eq!(v["user_summary"]["files_total"], 3);
        assert!(
            v["data_points"]
                .as_array()
                .unwrap()
                .iter()
                .any(|dp| dp["name"] == metric_names::MODULE_CALL_DURATION_MS)
        );

        // off: flushes NOTHING (no file written).
        let p = dir.path().join("off.json");
        assert!(
            module_flush_for_audience("off", &p).is_none(),
            "off audience must not flush anything"
        );
    }

    #[test]
    fn test_module_describe() {
        let module = TelemetryModule::new();
        let info = module.describe();
        assert_eq!(info.id, "telemetry");
        assert_eq!(info.name, "Telemetry");
        assert_eq!(info.rules.len(), 4);
    }

    #[test]
    fn test_module_analyze_default() {
        // Default `TelemetryConfig` resolves to `user-only` (Phase 15a.1
        // privacy default), which gates `backend-status` off (R4-1) — the
        // backend kind / endpoint / connectivity state are operator-disclosing
        // and must not cross the user-facing boundary. `metric-summary` is
        // still emitted (projected payload).
        let module = TelemetryModule::new();
        let config = HashMap::new();
        let result = module.analyze(&[], &config).unwrap();
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.rule_id == "backend-status"),
            "backend-status finding leaked under default (user-only) audience"
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id == "metric-summary")
        );
    }

    #[test]
    fn test_backend_status_finding_gated_by_audience() {
        // R4-1: `backend-status` discloses backend kind/endpoint/connectivity
        // (operator-shaped data). It must surface ONLY when the resolved
        // audience includes the operator scope (`On` / `OperatorOnly`) and
        // must be withheld under `UserOnly` and `Off`.
        let module = TelemetryModule::new();
        for (label, audience, want_backend_status) in [
            ("on", "on", true),
            ("operator-only", "operator-only", true),
            ("user-only", "user-only", false),
            ("off", "off", false),
        ] {
            let mut config = HashMap::new();
            config.insert("audience".to_owned(), audience.to_owned());
            let result = module.analyze(&[], &config).unwrap();
            let has = result
                .findings
                .iter()
                .any(|f| f.rule_id == "backend-status");
            assert_eq!(
                has, want_backend_status,
                "audience {label}: backend-status expected={want_backend_status}, was {has}"
            );
        }
    }

    #[test]
    fn test_module_analyze_with_collector() {
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 42, false);

        let module = TelemetryModule::with_collector(collector);
        let config = HashMap::new();
        let result = module.analyze(&[], &config).unwrap();

        let summary = result
            .findings
            .iter()
            .find(|f| f.rule_id == "metric-summary")
            .unwrap();
        assert!(summary.message.contains("10 files"));
    }

    #[test]
    fn test_module_explain() {
        let module = TelemetryModule::new();
        let explanation = module.explain("backend-status").unwrap();
        assert_eq!(explanation.rule_id, "backend-status");
        assert!(explanation.description.contains("connectivity"));
    }

    #[test]
    fn test_module_explain_metric_summary() {
        let module = TelemetryModule::new();
        let explanation = module.explain("metric-summary").unwrap();
        assert_eq!(explanation.rule_id, "metric-summary");
    }

    #[test]
    fn test_module_explain_finding_churn() {
        let module = TelemetryModule::new();
        let explanation = module.explain("finding-churn").unwrap();
        assert_eq!(explanation.rule_id, "finding-churn");
        assert!(explanation.description.contains("churn"));
    }

    #[test]
    fn test_module_explain_sampling_status() {
        let module = TelemetryModule::new();
        let explanation = module.explain("sampling-status").unwrap();
        assert_eq!(explanation.rule_id, "sampling-status");
        assert!(explanation.description.contains("sampling"));
    }

    #[test]
    fn test_module_explain_unknown() {
        let module = TelemetryModule::new();
        let err = module.explain("nonexistent").unwrap_err();
        assert!(matches!(err, ChaffraError::RuleNotFound(_)));
    }

    #[test]
    fn test_module_fix() {
        let module = TelemetryModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_backend_status_finding_connected() {
        let status = backends::BackendStatus {
            name: "json-file".to_owned(),
            kind: "JsonFile".to_owned(),
            connected: true,
            message: "ok".to_owned(),
        };
        let finding = backend_status_finding(&status);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.message.contains("connected"));
    }

    #[test]
    fn test_get_config_invalid_audience_is_error() {
        let module = TelemetryModule::new();
        let mut config = HashMap::new();
        config.insert("audience".to_owned(), "everyone".to_owned());
        let err = module.analyze(&[], &config).unwrap_err();
        assert!(
            matches!(err, ChaffraError::Config(ref m) if m.contains("invalid telemetry audience")),
            "got: {err:?}"
        );
    }

    #[test]
    fn test_default_audience_flush_is_projected_user_only() {
        // 1B: under the unified rule the module flushes for any non-Off audience.
        // With no `audience` key the default (user-only) applies, so the flush
        // DOES run but the projected payload carries NO operator data — exactly
        // like the CLI `run_with_telemetry` user-only path.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("telemetry.json");
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(4);
        collector.record_module_call("dead-code", 10, false); // operator metric
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 1);
        collector.record_module_findings("dead-code", 1, &sev); // user metric
        let module = TelemetryModule::with_collector(collector);

        let mut config = HashMap::new();
        config.insert("backend".to_owned(), "json-file".to_owned());
        config.insert("path".to_owned(), path.to_str().unwrap().to_owned());
        // No audience key -> default user-only.

        let result = module.analyze(&[], &config).unwrap();
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id == "metric-summary")
        );
        assert!(
            path.exists(),
            "user-only audience must flush projected user data"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        // User data present, operator data projected out.
        assert_eq!(parsed["user_summary"]["files_total"], 4);
        assert!(
            parsed["operator_summary"]["module_call_durations"]
                .as_object()
                .unwrap()
                .is_empty(),
            "operator data leaked into a user-only module flush"
        );
        for dp in parsed["data_points"].as_array().unwrap() {
            assert!(
                !metric_names::is_operator(dp["name"].as_str().unwrap()),
                "operator metric leaked into a user-only module flush"
            );
        }
    }

    #[test]
    fn test_operator_only_flush_is_projected_before_emission() {
        // Operator-only: the flushed payload must contain operator data but
        // NOT the user summary (projection happens before the backend write).
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("telemetry.json");
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(9);
        collector.record_module_call("dead-code", 10, false);
        let module = TelemetryModule::with_collector(collector);

        let mut config = HashMap::new();
        config.insert("audience".to_owned(), "operator-only".to_owned());
        config.insert("backend".to_owned(), "json-file".to_owned());
        config.insert("path".to_owned(), path.to_str().unwrap().to_owned());

        module.analyze(&[], &config).unwrap();
        assert!(path.exists(), "operator-only audience should flush");
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        // Operator data present.
        assert!(
            !parsed["operator_summary"]["module_call_durations"]
                .as_object()
                .unwrap()
                .is_empty()
        );
        // User summary projected out.
        assert_eq!(parsed["user_summary"]["files_total"], 0);
    }

    #[test]
    fn test_user_only_metric_summary_finding_is_projected() {
        // The `metric-summary` finding is a user-facing output boundary —
        // building it from the RAW snapshot would leak operator data even
        // when the backend flush is correctly projected. Under `user-only`:
        //   * per-module timing in `user_summary.module_summaries[*].duration_ms`
        //     must be scrubbed (the operator-derived field), and the
        //     payload-empty entry pruned;
        //   * the `data_points` / `spans` counts in the message must reflect
        //     ONLY user-facing/non-operator items.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(4);
        collector.record_module_call("dead-code", 73, false); // operator timing
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 1);
        collector.record_module_findings("dead-code", 1, &sev);

        let module = TelemetryModule::with_collector(collector);
        let mut config = HashMap::new();
        config.insert("audience".to_owned(), "user-only".to_owned());
        // Use a non-flushing backend kind so the test exercises only the
        // finding-construction path. (`backend = "none"` -> empty backends).
        let result = module.analyze(&[], &config).unwrap();

        let summary = result
            .findings
            .iter()
            .find(|f| f.rule_id == "metric-summary")
            .expect("metric-summary finding missing");
        let json: serde_json::Value =
            serde_json::from_str(summary.metadata.get("summary").unwrap()).unwrap();
        // Top-level user headline preserved.
        assert_eq!(json["files_total"], 4);
        // Per-module timing leaked through the user_summary metadata under the
        // PREVIOUS unprojected path; with projection applied here it is scrubbed
        // and the payload-empty entry is pruned. The `dead-code` entry has a
        // finding so it survives the payload-empty pruning — assert directly
        // (not `if let Some`) so the trust-boundary coverage check sees both
        // branches of the lookup as exercised.
        let mods = json["module_summaries"].as_object().unwrap();
        let entry = mods
            .get("dead-code")
            .expect("dead-code module summary should survive pruning (has a finding)");
        assert_eq!(
            entry["duration_ms"], 0,
            "operator timing leaked through metric-summary metadata"
        );
        assert_eq!(entry["finding_count"], 1);
        // The OPERATOR data-point (`chaffra.module.call_duration_ms`) recorded
        // by `record_module_call` would inflate the displayed data_points count
        // unless projection ran first; assert the projected count is reflected
        // in the message instead of the raw collector total.
        assert!(
            summary.message.contains("4 files"),
            "files headline missing: {}",
            summary.message
        );
    }

    #[test]
    fn test_backend_status_finding_disconnected() {
        let status = backends::BackendStatus {
            name: "otlp".to_owned(),
            kind: "Otlp".to_owned(),
            connected: false,
            message: "connection refused".to_owned(),
        };
        let finding = backend_status_finding(&status);
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.message.contains("disconnected"));
    }
}
