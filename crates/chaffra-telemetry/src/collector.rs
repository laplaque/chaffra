//! Telemetry collector: aggregates metrics and spans from all modules.

use crate::config::TelemetryConfig;
use crate::error::Result;
use crate::metrics::{MetricDataPoint, MetricDefinition, MetricKind, SpanData};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Aggregated telemetry snapshot from a single analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// When this snapshot was taken (unix ms).
    pub timestamp_ms: u64,
    /// Registered metric definitions keyed by name.
    pub definitions: HashMap<String, MetricDefinition>,
    /// All recorded data points.
    pub data_points: Vec<MetricDataPoint>,
    /// All recorded spans.
    pub spans: Vec<SpanData>,
    /// User-facing summary (finding counts, durations, scores).
    pub user_summary: UserSummary,
    /// Operator summary (call latencies, error rates).
    pub operator_summary: OperatorSummary,
}

/// User-facing telemetry summary included in analysis output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserSummary {
    /// Total analysis duration in milliseconds.
    pub analysis_duration_ms: u64,
    /// Total files analyzed.
    pub files_total: u64,
    /// Total findings by severity.
    pub findings_by_severity: HashMap<String, u64>,
    /// Total findings by module.
    pub findings_by_module: HashMap<String, u64>,
    /// Per-module breakdown.
    pub module_summaries: HashMap<String, ModuleSummary>,
}

/// Per-module summary for user-facing output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleSummary {
    /// Duration of this module's analysis in ms.
    pub duration_ms: u64,
    /// Number of findings.
    pub finding_count: u64,
    /// Module-specific metrics (e.g. health_score, clone_count).
    pub metrics: HashMap<String, f64>,
}

/// Operator-level telemetry sunk to backends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorSummary {
    /// Per-module call duration in ms.
    pub module_call_durations: HashMap<String, u64>,
    /// Per-module error counts.
    pub module_error_counts: HashMap<String, u64>,
}

impl TelemetrySnapshot {
    /// Return a copy with operator-level fields stripped.
    ///
    /// Removes `operator_summary`, `spans`, and raw `data_points` that contain
    /// operator-level detail (module call durations, error counts, etc.).
    /// Keeps `user_summary`, `definitions`, `timestamp_ms`, and user-scoped
    /// data points (findings, churn, cache metrics).
    pub fn user_scoped(&self) -> Self {
        let user_data_points = self
            .data_points
            .iter()
            .filter(|dp| {
                !dp.name.starts_with("chaffra.module.call_duration")
                    && !dp.name.starts_with("chaffra.module.error_total")
                    && !dp.name.starts_with("chaffra.module.load_error")
                    && !dp.name.starts_with("chaffra.plugin.connect_error")
                    && !dp.name.starts_with("chaffra.module.startup_duration")
                    && !dp.name.starts_with("chaffra.startup.total_duration")
            })
            .cloned()
            .collect();

        Self {
            timestamp_ms: self.timestamp_ms,
            definitions: self.definitions.clone(),
            data_points: user_data_points,
            spans: Vec::new(),
            user_summary: self.user_summary.clone(),
            operator_summary: OperatorSummary::default(),
        }
    }
}

/// Thread-safe telemetry collector.
///
/// Modules call `register_metrics`, `record_data_point`, and `record_span`
/// during analysis. After the run, `snapshot()` returns the aggregated state.
#[derive(Debug, Clone)]
pub struct TelemetryCollector {
    inner: Arc<Mutex<CollectorInner>>,
    config: TelemetryConfig,
}

#[derive(Debug, Default)]
struct CollectorInner {
    definitions: HashMap<String, MetricDefinition>,
    data_points: Vec<MetricDataPoint>,
    spans: Vec<SpanData>,
    module_durations: HashMap<String, u64>,
    module_errors: HashMap<String, u64>,
    module_findings: HashMap<String, u64>,
    findings_by_severity: HashMap<String, u64>,
    files_total: u64,
    analysis_start_ms: u64,
    finding_fingerprints: HashSet<crate::churn::FindingFingerprint>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl TelemetryCollector {
    /// Create a new collector with the given configuration.
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CollectorInner {
                analysis_start_ms: now_ms(),
                ..Default::default()
            })),
            config,
        }
    }

    /// Create a collector with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TelemetryConfig::default())
    }

    /// Get the current configuration.
    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    /// Register metric definitions from a module.
    pub fn register_metrics(
        &self,
        _module_id: &str,
        definitions: Vec<MetricDefinition>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        for def in definitions {
            inner.definitions.insert(def.name.clone(), def);
        }
        Ok(())
    }

    /// Record a single metric data point.
    pub fn record_data_point(&self, point: MetricDataPoint) {
        let mut inner = self.inner.lock().unwrap();
        inner.data_points.push(point);
    }

    /// Record multiple metric data points.
    pub fn record_data_points(&self, points: Vec<MetricDataPoint>) {
        let mut inner = self.inner.lock().unwrap();
        inner.data_points.extend(points);
    }

    /// Record a span.
    pub fn record_span(&self, span: SpanData) {
        let mut inner = self.inner.lock().unwrap();
        inner.spans.push(span);
    }

    /// Record multiple spans.
    pub fn record_spans(&self, spans: Vec<SpanData>) {
        let mut inner = self.inner.lock().unwrap();
        inner.spans.extend(spans);
    }

    /// Record a module call duration (called by the core after each module runs).
    pub fn record_module_call(&self, module_id: &str, duration_ms: u64, had_error: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .module_durations
            .insert(module_id.to_owned(), duration_ms);
        if had_error {
            *inner.module_errors.entry(module_id.to_owned()).or_insert(0) += 1;
        }

        // Record as data points.
        let ts = now_ms();
        inner.data_points.push(MetricDataPoint {
            name: "chaffra.module.call_duration_ms".to_owned(),
            value: duration_ms as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });

        if had_error {
            let error_count = inner.module_errors.get(module_id).copied().unwrap_or(1);
            inner.data_points.push(MetricDataPoint {
                name: "chaffra.module.error_total".to_owned(),
                value: error_count as f64,
                labels: {
                    let mut m = HashMap::new();
                    m.insert("module".to_owned(), module_id.to_owned());
                    m
                },
                timestamp_ms: ts,
            });
        }
    }

    /// Record findings from a module (called by the core after each module runs).
    pub fn record_module_findings(
        &self,
        module_id: &str,
        finding_count: u64,
        severity_counts: &HashMap<String, u64>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .module_findings
            .insert(module_id.to_owned(), finding_count);
        for (severity, count) in severity_counts {
            *inner
                .findings_by_severity
                .entry(severity.clone())
                .or_insert(0) += count;
        }

        let ts = now_ms();
        inner.data_points.push(MetricDataPoint {
            name: "chaffra.analysis.findings_total".to_owned(),
            value: finding_count as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });

        for (severity, count) in severity_counts {
            inner.data_points.push(MetricDataPoint {
                name: "chaffra.analysis.findings_by_severity".to_owned(),
                value: *count as f64,
                labels: {
                    let mut m = HashMap::new();
                    m.insert("module".to_owned(), module_id.to_owned());
                    m.insert("severity".to_owned(), severity.clone());
                    m
                },
                timestamp_ms: ts,
            });
        }
    }

    /// Set total files analyzed.
    pub fn set_files_total(&self, count: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.files_total = count;
    }

    /// Record a per-module summary metric (e.g. health_score, clone_count).
    pub fn record_module_summary_metric(&self, module_id: &str, key: &str, value: f64) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: format!("chaffra.module.{module_id}.{key}"),
            value,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Take a snapshot of all collected telemetry.
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let inner = self.inner.lock().unwrap();
        let now = now_ms();
        let analysis_duration = now.saturating_sub(inner.analysis_start_ms);

        // Build per-module summaries.
        let mut module_summaries = HashMap::new();
        for (module_id, &duration) in &inner.module_durations {
            let finding_count = inner.module_findings.get(module_id).copied().unwrap_or(0);

            // Collect module-specific metrics from data points.
            let prefix = format!("chaffra.module.{module_id}.");
            let mut metrics = HashMap::new();
            for dp in &inner.data_points {
                if let Some(key) = dp.name.strip_prefix(&prefix) {
                    metrics.insert(key.to_owned(), dp.value);
                }
            }

            module_summaries.insert(
                module_id.clone(),
                ModuleSummary {
                    duration_ms: duration,
                    finding_count,
                    metrics,
                },
            );
        }

        TelemetrySnapshot {
            timestamp_ms: now,
            definitions: inner.definitions.clone(),
            data_points: inner.data_points.clone(),
            spans: inner.spans.clone(),
            user_summary: UserSummary {
                analysis_duration_ms: analysis_duration,
                files_total: inner.files_total,
                findings_by_severity: inner.findings_by_severity.clone(),
                findings_by_module: inner.module_findings.clone(),
                module_summaries,
            },
            operator_summary: OperatorSummary {
                module_call_durations: inner.module_durations.clone(),
                module_error_counts: inner.module_errors.clone(),
            },
        }
    }

    /// Reset the collector for a new run.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        *inner = CollectorInner {
            analysis_start_ms: now_ms(),
            ..Default::default()
        };
    }

    /// Record a module load error.
    pub fn record_module_load_error(&self, module_id: &str, error_type: &str) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: "chaffra.module.load_error_total".to_owned(),
            value: 1.0,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m.insert("error_type".to_owned(), error_type.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Record a config parse error.
    pub fn record_config_parse_error(&self) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: "chaffra.config.parse_error_total".to_owned(),
            value: 1.0,
            labels: HashMap::new(),
            timestamp_ms: ts,
        });
    }

    /// Record a plugin (external module) connection error.
    pub fn record_plugin_connect_error(&self, module_id: &str) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: "chaffra.plugin.connect_error_total".to_owned(),
            value: 1.0,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Record per-module startup/initialization duration.
    pub fn record_module_startup(&self, module_id: &str, duration_ms: u64) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: "chaffra.module.startup_duration_ms".to_owned(),
            value: duration_ms as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Record total startup duration (all modules ready).
    pub fn record_startup_total(&self, duration_ms: u64) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: "chaffra.startup.total_duration_ms".to_owned(),
            value: duration_ms as f64,
            labels: HashMap::new(),
            timestamp_ms: ts,
        });
    }

    /// Record finding churn metrics from a churn result.
    pub fn record_finding_churn(&self, churn: &crate::churn::ChurnResult) {
        let ts = now_ms();
        let points = vec![
            MetricDataPoint {
                name: "chaffra.findings.new".to_owned(),
                value: churn.new_count as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.findings.resolved".to_owned(),
                value: churn.resolved_count as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.findings.unchanged".to_owned(),
                value: churn.unchanged_count as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.findings.churn_rate".to_owned(),
                value: churn.churn_rate,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
        ];
        self.record_data_points(points);
    }

    /// Store finding fingerprints produced by the current analysis run.
    pub fn set_finding_fingerprints(
        &self,
        fingerprints: HashSet<crate::churn::FindingFingerprint>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.finding_fingerprints = fingerprints;
    }

    /// Retrieve finding fingerprints stored during the current run.
    pub fn finding_fingerprints(&self) -> HashSet<crate::churn::FindingFingerprint> {
        let inner = self.inner.lock().unwrap();
        inner.finding_fingerprints.clone()
    }

    /// Register the core metric definitions.
    pub fn register_core_metrics(&self) {
        let defs = vec![
            MetricDefinition {
                name: "chaffra.analysis.duration_ms".to_owned(),
                kind: MetricKind::Histogram,
                description: "Total analysis duration".to_owned(),
                unit: "ms".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.analysis.files_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Total files analyzed".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.analysis.findings_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Total findings per module".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.analysis.findings_by_severity".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings per module and severity".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.module.call_duration_ms".to_owned(),
                kind: MetricKind::Histogram,
                description: "Per-module call duration".to_owned(),
                unit: "ms".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.module.error_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Per-module error count".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.new".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings not in previous run".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.resolved".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings in previous run but not current".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.unchanged".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings present in both runs".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.churn_rate".to_owned(),
                kind: MetricKind::Gauge,
                description: "Churn rate: new / (new + unchanged)".to_owned(),
                unit: "ratio".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.module.load_error_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Module load failures by module_id and error_type".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.config.parse_error_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Config parse failures".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.plugin.connect_error_total".to_owned(),
                kind: MetricKind::Counter,
                description: "External module gRPC connection failures".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.module.startup_duration_ms".to_owned(),
                kind: MetricKind::Histogram,
                description: "Per-module initialization time".to_owned(),
                unit: "ms".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.startup.total_duration_ms".to_owned(),
                kind: MetricKind::Gauge,
                description: "Total time from process start to all modules ready".to_owned(),
                unit: "ms".to_owned(),
            },
        ];
        let _ = self.register_metrics("core", defs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_basic() {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 42, false);

        let mut severity_counts = HashMap::new();
        severity_counts.insert("warning".to_owned(), 3);
        collector.record_module_findings("dead-code", 3, &severity_counts);

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.user_summary.files_total, 10);
        assert_eq!(
            snapshot.user_summary.findings_by_module.get("dead-code"),
            Some(&3)
        );
        assert_eq!(
            snapshot
                .operator_summary
                .module_call_durations
                .get("dead-code"),
            Some(&42)
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.analysis.duration_ms")
        );
    }

    #[test]
    fn test_collector_data_points() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_data_point(MetricDataPoint {
            name: "test.metric".to_owned(),
            value: 1.0,
            labels: HashMap::new(),
            timestamp_ms: 100,
        });
        collector.record_data_points(vec![
            MetricDataPoint {
                name: "test.metric".to_owned(),
                value: 2.0,
                labels: HashMap::new(),
                timestamp_ms: 200,
            },
            MetricDataPoint {
                name: "test.metric".to_owned(),
                value: 3.0,
                labels: HashMap::new(),
                timestamp_ms: 300,
            },
        ]);

        let snapshot = collector.snapshot();
        // 3 explicit + 0 implicit
        assert!(snapshot.data_points.len() >= 3);
    }

    #[test]
    fn test_collector_spans() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_span(SpanData {
            name: "test".to_owned(),
            trace_id: "t1".to_owned(),
            span_id: "s1".to_owned(),
            parent_span_id: String::new(),
            start_time_ms: 100,
            end_time_ms: 200,
            attributes: HashMap::new(),
            status: "ok".to_owned(),
        });

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.spans.len(), 1);
        assert_eq!(snapshot.spans[0].name, "test");
    }

    #[test]
    fn test_collector_reset() {
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(5);
        collector.record_module_call("test", 10, false);
        collector.reset();

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.user_summary.files_total, 0);
        assert!(snapshot.data_points.is_empty());
    }

    #[test]
    fn test_collector_module_summary_metric() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("complexity", 50, false);
        collector.record_module_summary_metric("complexity", "health_score", 85.0);
        collector.record_module_summary_metric("complexity", "cyclomatic_avg", 4.2);

        let snapshot = collector.snapshot();
        let summary = &snapshot.user_summary.module_summaries["complexity"];
        assert_eq!(summary.duration_ms, 50);
        assert!((summary.metrics["health_score"] - 85.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_collector_error_tracking() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("failing", 10, true);
        collector.record_module_call("failing", 20, true);

        let snapshot = collector.snapshot();
        assert_eq!(
            snapshot.operator_summary.module_error_counts.get("failing"),
            Some(&2)
        );
    }

    #[test]
    fn test_collector_module_load_error() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_load_error("security", "missing_dependency");
        let snapshot = collector.snapshot();
        let dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.module.load_error_total")
            .unwrap();
        assert!((dp.value - 1.0).abs() < f64::EPSILON);
        assert_eq!(dp.labels.get("module").unwrap(), "security");
        assert_eq!(dp.labels.get("error_type").unwrap(), "missing_dependency");
    }

    #[test]
    fn test_collector_config_parse_error() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_config_parse_error();
        let snapshot = collector.snapshot();
        assert!(
            snapshot
                .data_points
                .iter()
                .any(|p| p.name == "chaffra.config.parse_error_total")
        );
    }

    #[test]
    fn test_collector_plugin_connect_error() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_plugin_connect_error("fastapi-module");
        let snapshot = collector.snapshot();
        let dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.plugin.connect_error_total")
            .unwrap();
        assert_eq!(dp.labels.get("module").unwrap(), "fastapi-module");
    }

    #[test]
    fn test_collector_module_startup() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_startup("dead-code", 15);
        collector.record_module_startup("complexity", 8);
        let snapshot = collector.snapshot();
        let startup_points: Vec<_> = snapshot
            .data_points
            .iter()
            .filter(|p| p.name == "chaffra.module.startup_duration_ms")
            .collect();
        assert_eq!(startup_points.len(), 2);
    }

    #[test]
    fn test_collector_startup_total() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_startup_total(250);
        let snapshot = collector.snapshot();
        let dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.startup.total_duration_ms")
            .unwrap();
        assert!((dp.value - 250.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_collector_finding_churn() {
        let collector = TelemetryCollector::with_defaults();
        let churn = crate::churn::ChurnResult {
            new_count: 3,
            resolved_count: 1,
            unchanged_count: 5,
            churn_rate: 0.375,
        };
        collector.record_finding_churn(&churn);
        let snapshot = collector.snapshot();

        let new_dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.findings.new")
            .unwrap();
        assert!((new_dp.value - 3.0).abs() < f64::EPSILON);

        let rate_dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.findings.churn_rate")
            .unwrap();
        assert!((rate_dp.value - 0.375).abs() < f64::EPSILON);
    }

    #[test]
    fn test_core_metrics_include_phase13() {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        let snapshot = collector.snapshot();
        assert!(snapshot.definitions.contains_key("chaffra.findings.new"));
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.findings.churn_rate")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.module.load_error_total")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.module.startup_duration_ms")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.startup.total_duration_ms")
        );
    }

    #[test]
    fn test_collector_thread_safe() {
        let collector = TelemetryCollector::with_defaults();
        let c1 = collector.clone();
        let c2 = collector.clone();

        let t1 = std::thread::spawn(move || {
            c1.record_module_call("mod-a", 10, false);
        });
        let t2 = std::thread::spawn(move || {
            c2.record_module_call("mod-b", 20, false);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.operator_summary.module_call_durations.len(), 2);
    }
}
