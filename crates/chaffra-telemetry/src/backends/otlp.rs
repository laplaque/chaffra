//! OTLP (OpenTelemetry Protocol) payload backend (preview).
//!
//! Generates OTLP-compliant JSON payloads for metrics. Does not perform
//! network export in this version — use `inspect` to preview payloads for
//! integration with external collectors.

use super::TelemetryBackend;
use crate::collector::TelemetrySnapshot;
use crate::error::{Result, TelemetryError};

/// OTLP payload generator (preview — no network export yet).
#[derive(Debug)]
pub struct OtlpBackend {
    endpoint: String,
}

impl OtlpBackend {
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }

    /// Get the configured endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build the OTLP JSON payload for metrics.
    fn build_payload(&self, snapshot: &TelemetrySnapshot) -> serde_json::Value {
        let metrics: Vec<serde_json::Value> = snapshot
            .data_points
            .iter()
            .map(|dp| {
                let labels: serde_json::Value = dp
                    .labels
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!({
                            "key": k,
                            "value": { "stringValue": v }
                        })
                    })
                    .collect();

                serde_json::json!({
                    "name": dp.name,
                    "unit": "",
                    "gauge": {
                        "dataPoints": [{
                            "timeUnixNano": dp.timestamp_ms * 1_000_000,
                            "asDouble": dp.value,
                            "attributes": labels
                        }]
                    }
                })
            })
            .collect();

        serde_json::json!({
            "resourceMetrics": [{
                "resource": {
                    "attributes": [{
                        "key": "service.name",
                        "value": { "stringValue": "chaffra" }
                    }]
                },
                "scopeMetrics": [{
                    "scope": { "name": "chaffra-telemetry" },
                    "metrics": metrics
                }]
            }]
        })
    }
}

impl TelemetryBackend for OtlpBackend {
    fn name(&self) -> &str {
        "otlp"
    }

    fn flush(&self, snapshot: &TelemetrySnapshot) -> Result<()> {
        let payload = self.build_payload(snapshot);
        let json = serde_json::to_string(&payload)
            .map_err(|e| TelemetryError::BackendError(format!("OTLP payload error: {e}")))?;
        eprintln!(
            "[otlp] preview: generated {} byte OTLP payload for {} (network export not yet implemented)",
            json.len(),
            self.endpoint
        );
        Ok(())
    }

    fn test_connection(&self) -> Result<String> {
        Ok(format!(
            "OTLP endpoint configured: {} (preview mode — payload generation only, network export not yet implemented)",
            self.endpoint
        ))
    }

    fn inspect(&self, snapshot: &TelemetrySnapshot) -> Result<String> {
        let payload = self.build_payload(snapshot);
        Ok(serde_json::to_string_pretty(&payload)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::TelemetryCollector;
    use std::collections::HashMap;

    #[test]
    fn test_otlp_build_payload() {
        let backend = OtlpBackend::new("http://localhost:4317".to_owned());
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("dead-code", 42, false);
        let snapshot = collector.snapshot();

        let payload = backend.build_payload(&snapshot);
        assert!(payload["resourceMetrics"].is_array());
        let metrics = &payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        assert!(metrics.is_array());
    }

    #[test]
    fn test_otlp_inspect() {
        let backend = OtlpBackend::new("http://localhost:4317".to_owned());
        let collector = TelemetryCollector::with_defaults();
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 2);
        collector.record_module_findings("complexity", 2, &sev);
        let snapshot = collector.snapshot();

        let output = backend.inspect(&snapshot).unwrap();
        assert!(output.contains("resourceMetrics"));
        assert!(output.contains("chaffra"));
    }

    #[test]
    fn test_otlp_test_connection() {
        let backend = OtlpBackend::new("http://otel-collector:4317".to_owned());
        let result = backend.test_connection().unwrap();
        assert!(result.contains("otel-collector"));
    }
}
