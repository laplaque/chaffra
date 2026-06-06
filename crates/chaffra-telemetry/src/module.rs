//! `AnalysisModule` trait implementation for the telemetry module.
//!
//! The telemetry module is registered in the `GrpcModuleHost` like any other
//! module. Its `analyze` call returns the current telemetry snapshot as findings
//! (one info-level finding per configured backend with its status).

use crate::backends::{self, BackendStatus};
use crate::collector::TelemetryCollector;
use crate::config::TelemetryConfig;
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

    fn get_config(&self, config: &HashMap<String, String>) -> TelemetryConfig {
        TelemetryConfig::from_module_config(config)
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
            ],
        }
    }

    fn analyze(
        &self,
        _files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let tel_config = self.get_config(config);
        let collector = self.get_collector();

        // Create backends and check status.
        let (_backends, statuses) = backends::create_backends(&tel_config.backends);

        let mut findings = Vec::new();

        // Emit a finding per backend with its status.
        for status in &statuses {
            findings.push(backend_status_finding(status));
        }

        // Emit a summary finding with the current snapshot.
        let snapshot = collector.snapshot();
        let summary_json = serde_json::to_string_pretty(&snapshot.user_summary)
            .unwrap_or_else(|_| "{}".to_owned());

        findings.push(Finding {
            rule_id: "metric-summary".to_owned(),
            message: format!(
                "Telemetry: {} files, {} data points, {} spans",
                snapshot.user_summary.files_total,
                snapshot.data_points.len(),
                snapshot.spans.len(),
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

        // Flush to backends if operator telemetry is enabled.
        if tel_config.audience.operator_enabled() {
            let (active_backends, _) = backends::create_backends(&tel_config.backends);
            for backend in &active_backends {
                if let Err(e) = backend.flush(&snapshot) {
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
                description: "Summarizes the telemetry collected during the current analysis run, including file counts, finding counts, per-module durations, and span data.".to_owned(),
                rationale: "Provides a single finding that aggregates the full telemetry state for inspection or logging.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore metric-summary".to_owned(),
                examples: vec![
                    "Telemetry: 42 files, 15 data points, 3 spans".to_owned(),
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

    #[test]
    fn test_module_describe() {
        let module = TelemetryModule::new();
        let info = module.describe();
        assert_eq!(info.id, "telemetry");
        assert_eq!(info.name, "Telemetry");
        assert_eq!(info.rules.len(), 2);
    }

    #[test]
    fn test_module_analyze_default() {
        let module = TelemetryModule::new();
        let config = HashMap::new();
        let result = module.analyze(&[], &config).unwrap();
        // Should have at least one backend-status finding and one metric-summary finding.
        assert!(result.findings.len() >= 2);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id == "backend-status")
        );
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.rule_id == "metric-summary")
        );
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
