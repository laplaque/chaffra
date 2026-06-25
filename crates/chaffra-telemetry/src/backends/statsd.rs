//! StatsD UDP push backend.
//!
//! Sends metrics as StatsD-formatted datagrams over UDP.

use super::TelemetryBackend;
use crate::collector::{ProjectedSnapshot, TelemetrySnapshot};
use crate::error::{Result, TelemetryError};
use crate::metrics::MetricKind;

/// StatsD UDP backend.
#[derive(Debug)]
pub struct StatsdBackend {
    endpoint: String,
}

impl StatsdBackend {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    /// Get the configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Format metrics as StatsD lines.
    fn format_lines(&self, snapshot: &TelemetrySnapshot) -> Vec<String> {
        let mut lines = Vec::new();

        for dp in &snapshot.data_points {
            // Determine suffix from definition kind, defaulting to gauge.
            let kind_suffix = snapshot
                .definitions
                .get(&dp.name)
                .map(|def| match def.kind {
                    MetricKind::Counter => "c",
                    MetricKind::Gauge => "g",
                    MetricKind::Histogram => "ms",
                })
                .unwrap_or("g");

            // StatsD metric name: replace dots with underscores for some tools,
            // but dots are standard in modern StatsD.
            let tag_str = if dp.labels.is_empty() {
                String::new()
            } else {
                let tags: Vec<String> = dp.labels.iter().map(|(k, v)| format!("{k}:{v}")).collect();
                format!("|#{}", tags.join(","))
            };

            lines.push(format!("{}:{}|{kind_suffix}{tag_str}", dp.name, dp.value));
        }

        lines
    }
}

impl TelemetryBackend for StatsdBackend {
    fn name(&self) -> &str {
        "statsd"
    }

    fn flush(&self, snapshot: &ProjectedSnapshot) -> Result<()> {
        let snapshot = snapshot.inner();
        let lines = self.format_lines(snapshot);
        if lines.is_empty() {
            return Ok(());
        }

        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| TelemetryError::BackendError(format!("UDP bind failed: {e}")))?;

        for line in &lines {
            if let Err(e) = socket.send_to(line.as_bytes(), &self.endpoint) {
                eprintln!("[statsd] send error: {e}");
            }
        }

        Ok(())
    }

    fn test_connection(&self) -> Result<String> {
        // Attempt to bind a UDP socket (does not actually connect).
        let _socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| TelemetryError::BackendError(format!("UDP bind failed: {e}")))?;
        Ok(format!("StatsD endpoint configured: {}", self.endpoint))
    }

    fn inspect(&self, snapshot: &ProjectedSnapshot) -> Result<String> {
        let snapshot = snapshot.inner();
        let lines = self.format_lines(snapshot);
        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::TelemetryCollector;

    #[test]
    fn test_statsd_format_lines() {
        let backend = StatsdBackend::new("127.0.0.1:8125".to_owned());
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.record_module_call("dead-code", 42, false);
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);

        let lines = backend.format_lines(&snapshot);
        assert!(!lines.is_empty());
        // Should contain the module call duration metric.
        let has_duration = lines.iter().any(|l| l.contains("call_duration_ms"));
        assert!(has_duration, "lines: {lines:?}");
    }

    #[test]
    fn test_statsd_inspect() {
        let backend = StatsdBackend::new("127.0.0.1:8125".to_owned());
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("test", 10, false);
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);

        let output = backend.inspect(&snapshot).unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_statsd_test_connection() {
        let backend = StatsdBackend::new("127.0.0.1:8125".to_owned());
        let result = backend.test_connection().unwrap();
        assert!(result.contains("StatsD"));
    }

    #[test]
    fn test_statsd_backend_flush_ok() {
        // R5-Structural coverage: exercise the `flush()` entry point with a
        // `ProjectedSnapshot`. The StatsD flush binds a UDP socket and emits
        // datagrams to the configured endpoint; binding 0.0.0.0:0 doesn't
        // need network access and send_to errors are logged-not-returned, so
        // the test asserts Ok regardless of whether anything listens on the
        // localhost port.
        let backend = StatsdBackend::new("127.0.0.1:8125".to_owned());
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.record_module_call("dead-code", 42, false);
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);
        backend.flush(&snapshot).unwrap();
    }
}
