//! Prometheus exposition backend.
//!
//! Generates text in Prometheus exposition format. In watch/server mode this
//! would be served on a `/metrics` HTTP endpoint. For one-shot CLI runs it
//! writes the exposition text to a file or returns it for inspection.

use super::TelemetryBackend;
use crate::collector::{ProjectedSnapshot, TelemetrySnapshot};
use crate::error::Result;
use crate::metrics::MetricKind;

/// Prometheus exposition format backend.
#[derive(Debug)]
pub struct PrometheusBackend {
    port: u16,
}

impl PrometheusBackend {
    pub fn new(port: u16) -> Self {
        Self { port }
    }

    /// Get the configured port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Render all metrics in Prometheus exposition text format.
    fn render_exposition(&self, snapshot: &TelemetrySnapshot) -> String {
        let mut output = String::new();

        // Emit HELP and TYPE lines from definitions, then values from data points.
        for (name, def) in &snapshot.definitions {
            let prom_type = match def.kind {
                MetricKind::Counter => "counter",
                MetricKind::Gauge => "gauge",
                MetricKind::Histogram => "histogram",
            };
            let safe_name = name.replace('.', "_");
            output.push_str(&format!("# HELP {safe_name} {}\n", def.description));
            output.push_str(&format!("# TYPE {safe_name} {prom_type}\n"));
        }

        // Emit data points as metric lines.
        for dp in &snapshot.data_points {
            let safe_name = dp.name.replace('.', "_");
            if dp.labels.is_empty() {
                output.push_str(&format!("{safe_name} {}\n", dp.value));
            } else {
                let label_str: Vec<String> = dp
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{v}\""))
                    .collect();
                output.push_str(&format!(
                    "{safe_name}{{{labels}}} {value}\n",
                    labels = label_str.join(","),
                    value = dp.value
                ));
            }
        }

        output
    }

    /// Audience-neutral flush log line (R9-F1): omits the operator-shaped
    /// `port`, since the live flush path runs under `user-only` too. The port
    /// stays on the operator-gated `test_connection` / `inspect` surfaces.
    fn flush_log_line(byte_len: usize) -> String {
        format!("[prometheus] exposition ready ({byte_len} bytes)")
    }
}

impl TelemetryBackend for PrometheusBackend {
    fn name(&self) -> &str {
        "prometheus"
    }

    fn flush(&self, snapshot: &ProjectedSnapshot) -> Result<()> {
        let snapshot = snapshot.inner();
        // In a full implementation this would update an in-memory registry
        // served by the HTTP endpoint. For now, we log the exposition text
        // to signal readiness.
        let text = self.render_exposition(snapshot);
        eprintln!("{}", Self::flush_log_line(text.len()));
        Ok(())
    }

    fn test_connection(&self) -> Result<String> {
        Ok(format!(
            "prometheus exposition on port {} (active in watch/server mode only)",
            self.port
        ))
    }

    fn inspect(&self, snapshot: &ProjectedSnapshot) -> Result<String> {
        let snapshot = snapshot.inner();
        Ok(self.render_exposition(snapshot))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::TelemetryCollector;

    #[test]
    fn test_prometheus_render() {
        let backend = PrometheusBackend::new(9090);
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 42, false);

        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);
        let text = backend.render_exposition(&snapshot);

        assert!(text.contains("# HELP"));
        assert!(text.contains("# TYPE"));
        assert!(text.contains("chaffra_module_call_duration_ms"));
    }

    #[test]
    fn test_prometheus_inspect() {
        let backend = PrometheusBackend::new(9090);
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);

        let output = backend.inspect(&snapshot).unwrap();
        assert!(output.contains("# HELP"));
    }

    #[test]
    fn test_prometheus_test_connection() {
        let backend = PrometheusBackend::new(9090);
        let result = backend.test_connection().unwrap();
        assert!(result.contains("9090"));
    }

    #[test]
    fn test_prometheus_backend_flush_ok() {
        // R5-Structural coverage: exercise the `flush()` entry point with a
        // `ProjectedSnapshot`. The Prometheus exposition flush logs the
        // generated text size to stderr; assert Ok.
        let backend = PrometheusBackend::new(9090);
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(10);
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);
        backend.flush(&snapshot).unwrap();
    }

    #[test]
    fn test_prometheus_flush_log_omits_port() {
        // R9-F1: the operator-shaped port must not appear in the live flush log.
        let backend = PrometheusBackend::new(59090);
        let line = PrometheusBackend::flush_log_line(123);
        assert!(
            !line.contains(&backend.port.to_string()),
            "flush log leaked the Prometheus port: {line}"
        );
    }
}
