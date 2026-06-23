//! Metric and span data types for telemetry collection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Canonical names of the metrics chaffra produces, split by audience scope.
///
/// These constants are the single source of truth for metric naming: every
/// producer (the collector, the parse-cache flush, the core definition
/// registry) names its data points and definitions from here, and the audience
/// classifier in [`crate::collector`] decides operator-vs-user scope from the
/// same set. Because producer and classifier share these symbols, a rename
/// cannot silently desynchronise the two — a typo is a compile error, not a
/// privacy leak.
pub mod metric_names {
    /// Operator-scoped metric names: process- and environment-shaped telemetry
    /// (call latencies, error/connection/startup counters, cache pressure) that
    /// is withheld from any audience without the operator scope.
    ///
    /// Matching is by EXACT name, not prefix: each of these is a complete metric
    /// name whose dimensional variation lives in labels, never in a name suffix.
    /// Exact matching prevents a per-module summary metric such as
    /// `chaffra.module.<id>.<key>` (e.g. a module whose id is `error_total`)
    /// from colliding with an operator name like `chaffra.module.error_total`.
    pub const OPERATOR: &[&str] = &[
        MODULE_CALL_DURATION_MS,
        MODULE_ERROR_TOTAL,
        MODULE_STARTUP_DURATION_MS,
        MODULE_LOAD_ERROR_TOTAL,
        STARTUP_TOTAL_DURATION_MS,
        PLUGIN_CONNECT_ERROR_TOTAL,
        CONFIG_PARSE_ERROR_TOTAL,
        PARSE_CACHE_HITS,
        PARSE_CACHE_MISSES,
        PARSE_CACHE_HIT_RATE,
        PARSE_CACHE_SIZE_BYTES,
        PARSE_CACHE_EVICTIONS,
    ];

    pub const MODULE_CALL_DURATION_MS: &str = "chaffra.module.call_duration_ms";
    pub const MODULE_ERROR_TOTAL: &str = "chaffra.module.error_total";
    pub const MODULE_STARTUP_DURATION_MS: &str = "chaffra.module.startup_duration_ms";
    pub const MODULE_LOAD_ERROR_TOTAL: &str = "chaffra.module.load_error_total";
    pub const STARTUP_TOTAL_DURATION_MS: &str = "chaffra.startup.total_duration_ms";
    pub const PLUGIN_CONNECT_ERROR_TOTAL: &str = "chaffra.plugin.connect_error_total";
    pub const CONFIG_PARSE_ERROR_TOTAL: &str = "chaffra.config.parse_error_total";
    pub const PARSE_CACHE_HITS: &str = "chaffra.parse.cache_hits";
    pub const PARSE_CACHE_MISSES: &str = "chaffra.parse.cache_misses";
    pub const PARSE_CACHE_HIT_RATE: &str = "chaffra.parse.cache_hit_rate";
    pub const PARSE_CACHE_SIZE_BYTES: &str = "chaffra.parse.cache_size_bytes";
    pub const PARSE_CACHE_EVICTIONS: &str = "chaffra.parse.cache_evictions";

    /// Whether a metric NAME is operator-scoped (exact match against
    /// [`OPERATOR`]).
    #[must_use]
    pub fn is_operator(name: &str) -> bool {
        OPERATOR.contains(&name)
    }
}

/// Kind of metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

/// Definition of a metric that a module can register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDefinition {
    /// Dotted metric name, e.g. `chaffra.analysis.duration_ms`.
    pub name: String,
    /// Kind of metric.
    pub kind: MetricKind,
    /// Human-readable description.
    pub description: String,
    /// Unit (e.g. "ms", "count", "bytes").
    pub unit: String,
}

/// A single data point for a metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricDataPoint {
    /// Metric name.
    pub name: String,
    /// Numeric value.
    pub value: f64,
    /// Dimensional labels (module, severity, etc.).
    pub labels: HashMap<String, String>,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
}

/// A trace span for distributed tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanData {
    /// Span name (e.g. "dead-code.analyze").
    pub name: String,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Unique span ID.
    pub span_id: String,
    /// Parent span ID (empty if root).
    pub parent_span_id: String,
    /// Start time in unix milliseconds.
    pub start_time_ms: u64,
    /// End time in unix milliseconds.
    pub end_time_ms: u64,
    /// Key-value attributes.
    pub attributes: HashMap<String, String>,
    /// Status: "ok", "error", "unset".
    pub status: String,
}

impl SpanData {
    /// Duration of this span in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.end_time_ms.saturating_sub(self.start_time_ms)
    }
}

/// Convert from proto MetricKind enum.
pub fn metric_kind_from_proto(v: i32) -> MetricKind {
    match v {
        1 => MetricKind::Counter,
        2 => MetricKind::Gauge,
        3 => MetricKind::Histogram,
        _ => MetricKind::Counter,
    }
}

/// Convert to proto MetricKind enum value.
pub fn metric_kind_to_proto(kind: MetricKind) -> i32 {
    match kind {
        MetricKind::Counter => 1,
        MetricKind::Gauge => 2,
        MetricKind::Histogram => 3,
    }
}

/// Convert a proto MetricDataPoint to our domain type.
pub fn data_point_from_proto(p: &chaffra_proto::proto::MetricDataPoint) -> MetricDataPoint {
    MetricDataPoint {
        name: p.name.clone(),
        value: p.value,
        labels: p.labels.clone(),
        timestamp_ms: p.timestamp_ms,
    }
}

/// Convert our domain MetricDataPoint to proto.
pub fn data_point_to_proto(p: &MetricDataPoint) -> chaffra_proto::proto::MetricDataPoint {
    chaffra_proto::proto::MetricDataPoint {
        name: p.name.clone(),
        value: p.value,
        labels: p.labels.clone(),
        timestamp_ms: p.timestamp_ms,
    }
}

/// Convert a proto SpanData to our domain type.
pub fn span_from_proto(s: &chaffra_proto::proto::SpanData) -> SpanData {
    SpanData {
        name: s.name.clone(),
        trace_id: s.trace_id.clone(),
        span_id: s.span_id.clone(),
        parent_span_id: s.parent_span_id.clone(),
        start_time_ms: s.start_time_ms,
        end_time_ms: s.end_time_ms,
        attributes: s.attributes.clone(),
        status: s.status.clone(),
    }
}

/// Convert our domain SpanData to proto.
pub fn span_to_proto(s: &SpanData) -> chaffra_proto::proto::SpanData {
    chaffra_proto::proto::SpanData {
        name: s.name.clone(),
        trace_id: s.trace_id.clone(),
        span_id: s.span_id.clone(),
        parent_span_id: s.parent_span_id.clone(),
        start_time_ms: s.start_time_ms,
        end_time_ms: s.end_time_ms,
        attributes: s.attributes.clone(),
        status: s.status.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_names_operator_set_exact_match() {
        // Every name in the OPERATOR set classifies as operator.
        for name in metric_names::OPERATOR {
            assert!(
                metric_names::is_operator(name),
                "{name} should be operator-scoped"
            );
        }
        // The full parse-cache family is now covered.
        for name in [
            metric_names::PARSE_CACHE_HITS,
            metric_names::PARSE_CACHE_MISSES,
            metric_names::PARSE_CACHE_HIT_RATE,
            metric_names::PARSE_CACHE_SIZE_BYTES,
            metric_names::PARSE_CACHE_EVICTIONS,
        ] {
            assert!(metric_names::is_operator(name), "{name} should be operator");
        }
    }

    #[test]
    fn test_metric_names_user_facing_not_operator() {
        for name in [
            "chaffra.analysis.findings_total",
            "chaffra.analysis.findings_by_severity",
            "chaffra.findings.churn_rate",
            "chaffra.module.dead-code.unused_functions",
        ] {
            assert!(
                !metric_names::is_operator(name),
                "{name} should be user-facing"
            );
        }
    }

    #[test]
    fn test_metric_names_no_prefix_collision() {
        // A module whose id collides with an operator metric name produces a
        // per-module summary metric `chaffra.module.<id>.<key>`. Exact matching
        // must NOT misclassify it as the operator metric `chaffra.module.error_total`.
        assert!(metric_names::is_operator(metric_names::MODULE_ERROR_TOTAL));
        assert!(!metric_names::is_operator(
            "chaffra.module.error_total.health_score"
        ));
        assert!(!metric_names::is_operator(
            "chaffra.startup.total_duration_ms.extra"
        ));
    }

    #[test]
    fn test_span_duration() {
        let span = SpanData {
            name: "test".to_owned(),
            trace_id: "t1".to_owned(),
            span_id: "s1".to_owned(),
            parent_span_id: String::new(),
            start_time_ms: 1000,
            end_time_ms: 1500,
            attributes: HashMap::new(),
            status: "ok".to_owned(),
        };
        assert_eq!(span.duration_ms(), 500);
    }

    #[test]
    fn test_metric_kind_roundtrip() {
        for kind in [
            MetricKind::Counter,
            MetricKind::Gauge,
            MetricKind::Histogram,
        ] {
            let proto_val = metric_kind_to_proto(kind);
            let restored = metric_kind_from_proto(proto_val);
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn test_data_point_roundtrip() {
        let dp = MetricDataPoint {
            name: "chaffra.test.metric".to_owned(),
            value: 42.5,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), "dead-code".to_owned());
                m
            },
            timestamp_ms: 1700000000000,
        };
        let proto = data_point_to_proto(&dp);
        let restored = data_point_from_proto(&proto);
        assert_eq!(dp.name, restored.name);
        assert!((dp.value - restored.value).abs() < f64::EPSILON);
        assert_eq!(dp.labels, restored.labels);
        assert_eq!(dp.timestamp_ms, restored.timestamp_ms);
    }

    #[test]
    fn test_span_roundtrip() {
        let span = SpanData {
            name: "analyze".to_owned(),
            trace_id: "trace-1".to_owned(),
            span_id: "span-1".to_owned(),
            parent_span_id: "parent-1".to_owned(),
            start_time_ms: 100,
            end_time_ms: 200,
            attributes: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), "complexity".to_owned());
                m
            },
            status: "ok".to_owned(),
        };
        let proto = span_to_proto(&span);
        let restored = span_from_proto(&proto);
        assert_eq!(span.name, restored.name);
        assert_eq!(span.trace_id, restored.trace_id);
        assert_eq!(span.span_id, restored.span_id);
        assert_eq!(span.parent_span_id, restored.parent_span_id);
        assert_eq!(span.start_time_ms, restored.start_time_ms);
        assert_eq!(span.end_time_ms, restored.end_time_ms);
        assert_eq!(span.attributes, restored.attributes);
        assert_eq!(span.status, restored.status);
    }
}
