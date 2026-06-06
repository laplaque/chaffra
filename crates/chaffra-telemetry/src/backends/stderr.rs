//! Stderr structured log backend: JSON lines for CI ingestion.

use super::TelemetryBackend;
use crate::collector::TelemetrySnapshot;
use crate::error::Result;

/// Writes telemetry as JSON lines to stderr.
#[derive(Debug)]
pub struct StderrBackend;

impl StderrBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StderrBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetryBackend for StderrBackend {
    fn name(&self) -> &str {
        "stderr"
    }

    fn flush(&self, snapshot: &TelemetrySnapshot) -> Result<()> {
        // Emit each data point as a separate JSON line for easy parsing.
        for dp in &snapshot.data_points {
            let line = serde_json::to_string(dp)?;
            eprintln!("{line}");
        }

        // Emit summary line.
        let summary = serde_json::json!({
            "event": "chaffra.telemetry.summary",
            "timestamp_ms": snapshot.timestamp_ms,
            "files_total": snapshot.user_summary.files_total,
            "analysis_duration_ms": snapshot.user_summary.analysis_duration_ms,
            "findings_by_severity": snapshot.user_summary.findings_by_severity,
            "findings_by_module": snapshot.user_summary.findings_by_module,
        });
        eprintln!("{}", serde_json::to_string(&summary)?);

        Ok(())
    }

    fn test_connection(&self) -> Result<String> {
        Ok("stderr is always available".to_owned())
    }

    fn inspect(&self, snapshot: &TelemetrySnapshot) -> Result<String> {
        let mut lines = Vec::new();
        for dp in &snapshot.data_points {
            lines.push(serde_json::to_string(dp)?);
        }
        let summary = serde_json::json!({
            "event": "chaffra.telemetry.summary",
            "timestamp_ms": snapshot.timestamp_ms,
            "files_total": snapshot.user_summary.files_total,
            "analysis_duration_ms": snapshot.user_summary.analysis_duration_ms,
        });
        lines.push(serde_json::to_string(&summary)?);
        Ok(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::TelemetryCollector;

    #[test]
    fn test_stderr_backend_name() {
        let backend = StderrBackend::new();
        assert_eq!(backend.name(), "stderr");
    }

    #[test]
    fn test_stderr_backend_test_connection() {
        let backend = StderrBackend::new();
        let result = backend.test_connection().unwrap();
        assert!(result.contains("always available"));
    }

    #[test]
    fn test_stderr_backend_inspect() {
        let backend = StderrBackend::new();
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(3);
        let snapshot = collector.snapshot();

        let output = backend.inspect(&snapshot).unwrap();
        assert!(output.contains("chaffra.telemetry.summary"));
    }
}
