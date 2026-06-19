//! Metric and span data types for telemetry collection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    /// Whether this metric is user-scoped (true) or operator-only (false).
    /// Unknown/unclassified metrics default to operator-only (fail-closed).
    #[serde(default)]
    pub user_scoped: bool,
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
        user_scoped: p.user_scoped,
    }
}

/// Convert our domain MetricDataPoint to proto.
pub fn data_point_to_proto(p: &MetricDataPoint) -> chaffra_proto::proto::MetricDataPoint {
    chaffra_proto::proto::MetricDataPoint {
        name: p.name.clone(),
        value: p.value,
        labels: p.labels.clone(),
        timestamp_ms: p.timestamp_ms,
        user_scoped: p.user_scoped,
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
            user_scoped: false,
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
