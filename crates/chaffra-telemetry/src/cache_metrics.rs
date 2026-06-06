use crate::collector::TelemetryCollector;
use crate::metrics::{MetricDefinition, MetricKind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone)]
pub struct ParseCacheMetrics {
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    evictions: Arc<AtomicU64>,
    size_bytes: Arc<AtomicU64>,
}

impl ParseCacheMetrics {
    pub fn new() -> Self {
        Self {
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            evictions: Arc::new(AtomicU64::new(0)),
            size_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_size_bytes(&self, bytes: u64) {
        self.size_bytes.store(bytes, Ordering::Relaxed);
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes.load(Ordering::Relaxed)
    }

    pub fn hit_rate(&self) -> f64 {
        let h = self.hits() as f64;
        let m = self.misses() as f64;
        let total = h + m;
        if total == 0.0 { 0.0 } else { h / total }
    }

    pub fn flush_to_collector(&self, collector: &TelemetryCollector) {
        use crate::metrics::MetricDataPoint;
        use std::collections::HashMap;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let points = vec![
            MetricDataPoint {
                name: "chaffra.parse.cache_hits".to_owned(),
                value: self.hits() as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.parse.cache_misses".to_owned(),
                value: self.misses() as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.parse.cache_hit_rate".to_owned(),
                value: self.hit_rate(),
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.parse.cache_size_bytes".to_owned(),
                value: self.size_bytes() as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.parse.cache_evictions".to_owned(),
                value: self.evictions() as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
        ];

        collector.record_data_points(points);
    }
}

impl Default for ParseCacheMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub fn register_cache_metrics(collector: &TelemetryCollector) {
    let definitions = vec![
        MetricDefinition {
            name: "chaffra.parse.cache_hits".to_owned(),
            kind: MetricKind::Counter,
            description: "Files served from parse cache".to_owned(),
            unit: "count".to_owned(),
        },
        MetricDefinition {
            name: "chaffra.parse.cache_misses".to_owned(),
            kind: MetricKind::Counter,
            description: "Files re-parsed (cache miss)".to_owned(),
            unit: "count".to_owned(),
        },
        MetricDefinition {
            name: "chaffra.parse.cache_hit_rate".to_owned(),
            kind: MetricKind::Gauge,
            description: "Cache hit rate (hits / total)".to_owned(),
            unit: "ratio".to_owned(),
        },
        MetricDefinition {
            name: "chaffra.parse.cache_size_bytes".to_owned(),
            kind: MetricKind::Gauge,
            description: "Current parse cache memory usage".to_owned(),
            unit: "bytes".to_owned(),
        },
        MetricDefinition {
            name: "chaffra.parse.cache_evictions".to_owned(),
            kind: MetricKind::Counter,
            description: "Parse cache entries evicted".to_owned(),
            unit: "count".to_owned(),
        },
    ];

    let _ = collector.register_metrics("parse-cache", definitions);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_metrics_basic() {
        let metrics = ParseCacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();

        assert_eq!(metrics.hits(), 2);
        assert_eq!(metrics.misses(), 1);
        assert!((metrics.hit_rate() - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_metrics_zero_total() {
        let metrics = ParseCacheMetrics::new();
        assert_eq!(metrics.hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_metrics_evictions_and_size() {
        let metrics = ParseCacheMetrics::new();

        metrics.set_size_bytes(1024);
        assert_eq!(metrics.size_bytes(), 1024);

        metrics.record_eviction();
        metrics.record_eviction();
        assert_eq!(metrics.evictions(), 2);
    }

    #[test]
    fn test_flush_to_collector() {
        let collector = TelemetryCollector::with_defaults();
        let metrics = ParseCacheMetrics::new();

        metrics.record_hit();
        metrics.record_hit();
        metrics.record_miss();
        metrics.set_size_bytes(2048);
        metrics.record_eviction();

        register_cache_metrics(&collector);
        metrics.flush_to_collector(&collector);

        let snapshot = collector.snapshot();
        let cache_points: Vec<_> = snapshot
            .data_points
            .iter()
            .filter(|p| p.name.starts_with("chaffra.parse.cache"))
            .collect();

        assert_eq!(cache_points.len(), 5);

        let hit_point = cache_points
            .iter()
            .find(|p| p.name == "chaffra.parse.cache_hits")
            .unwrap();
        assert_eq!(hit_point.value, 2.0);

        let rate_point = cache_points
            .iter()
            .find(|p| p.name == "chaffra.parse.cache_hit_rate")
            .unwrap();
        assert!((rate_point.value - 2.0 / 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_register_cache_metrics() {
        let collector = TelemetryCollector::with_defaults();
        register_cache_metrics(&collector);

        let snapshot = collector.snapshot();
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.parse.cache_hits")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.parse.cache_misses")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.parse.cache_hit_rate")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.parse.cache_size_bytes")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.parse.cache_evictions")
        );
    }
}
