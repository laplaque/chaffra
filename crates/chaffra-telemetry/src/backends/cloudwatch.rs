//! AWS CloudWatch payload backend (preview, behind `cloudwatch` feature flag).
//!
//! Generates PutMetricData-compatible JSON payloads. Does not perform network
//! calls in this version — use `inspect` to preview payloads.

use super::TelemetryBackend;
use crate::collector::TelemetrySnapshot;
use crate::error::{Result, TelemetryError};

/// AWS CloudWatch payload generator (preview — no network calls yet).
#[derive(Debug)]
pub struct CloudWatchBackend {
    namespace: String,
    region: Option<String>,
}

impl CloudWatchBackend {
    pub fn new(namespace: String, region: Option<String>) -> Self {
        Self { namespace, region }
    }

    /// Build a PutMetricData-like JSON payload.
    fn build_payload(&self, snapshot: &TelemetrySnapshot) -> serde_json::Value {
        let metric_data: Vec<serde_json::Value> = snapshot
            .data_points
            .iter()
            .map(|dp| {
                let dimensions: Vec<serde_json::Value> = dp
                    .labels
                    .iter()
                    .map(|(k, v)| {
                        serde_json::json!({
                            "Name": k,
                            "Value": v
                        })
                    })
                    .collect();

                serde_json::json!({
                    "MetricName": dp.name,
                    "Value": dp.value,
                    "Dimensions": dimensions,
                    "Timestamp": dp.timestamp_ms / 1000
                })
            })
            .collect();

        serde_json::json!({
            "Namespace": self.namespace,
            "MetricData": metric_data
        })
    }
}

impl TelemetryBackend for CloudWatchBackend {
    fn name(&self) -> &str {
        "cloudwatch"
    }

    fn flush(&self, snapshot: &TelemetrySnapshot) -> Result<()> {
        let payload = self.build_payload(snapshot);
        let json = serde_json::to_string(&payload)
            .map_err(|e| TelemetryError::BackendError(format!("CloudWatch payload error: {e}")))?;
        eprintln!(
            "[cloudwatch] preview: generated {} byte PutMetricData payload for namespace '{}' (network export not yet implemented)",
            json.len(),
            self.namespace
        );
        Ok(())
    }

    fn test_connection(&self) -> Result<String> {
        let region_str = self.region.as_deref().unwrap_or("default");
        Ok(format!(
            "CloudWatch namespace '{}' (region: {region_str}) (preview mode — payload generation only, network export not yet implemented)",
            self.namespace
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

    #[test]
    fn test_cloudwatch_build_payload() {
        let backend = CloudWatchBackend::new("chaffra".to_owned(), Some("us-east-1".to_owned()));
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("dead-code", 50, false);
        let snapshot = collector.snapshot();

        let payload = backend.build_payload(&snapshot);
        assert_eq!(payload["Namespace"], "chaffra");
        assert!(payload["MetricData"].is_array());
    }

    #[test]
    fn test_cloudwatch_inspect() {
        let backend = CloudWatchBackend::new("chaffra".to_owned(), None);
        let collector = TelemetryCollector::with_defaults();
        let snapshot = collector.snapshot();

        let output = backend.inspect(&snapshot).unwrap();
        assert!(output.contains("chaffra"));
    }

    #[test]
    fn test_cloudwatch_test_connection() {
        let backend = CloudWatchBackend::new("my-ns".to_owned(), Some("eu-west-1".to_owned()));
        let result = backend.test_connection().unwrap();
        assert!(result.contains("my-ns"));
        assert!(result.contains("eu-west-1"));
    }
}
