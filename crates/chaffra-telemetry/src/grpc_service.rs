//! gRPC `TelemetryCollector` service implementation.
//!
//! Implements the `TelemetryCollector` gRPC service defined in module.proto.
//! Receives metric registrations, data points, and spans from modules.

use crate::MetricDefinition;
use crate::collector::TelemetryCollector;
use crate::metrics::{data_point_from_proto, metric_kind_from_proto, span_from_proto};

use chaffra_proto::proto::telemetry_collector_server;

/// gRPC service that delegates to a `TelemetryCollector`.
pub struct TelemetryGrpcService {
    collector: TelemetryCollector,
}

impl TelemetryGrpcService {
    pub fn new(collector: TelemetryCollector) -> Self {
        Self { collector }
    }
}

#[tonic::async_trait]
impl telemetry_collector_server::TelemetryCollector for TelemetryGrpcService {
    async fn register_metrics(
        &self,
        request: tonic::Request<chaffra_proto::proto::RegisterMetricsRequest>,
    ) -> std::result::Result<
        tonic::Response<chaffra_proto::proto::RegisterMetricsResponse>,
        tonic::Status,
    > {
        let req = request.into_inner();
        let definitions: Vec<MetricDefinition> = req
            .definitions
            .iter()
            .map(|d| MetricDefinition {
                name: d.name.clone(),
                kind: metric_kind_from_proto(d.kind),
                description: d.description.clone(),
                unit: d.unit.clone(),
            })
            .collect();

        // External module definition submissions are UNTRUSTED, just like data
        // points received on `record_metrics` (R3-3). Route them through the
        // provenance-tracking ingress so the snapshot projection fails them
        // closed at every restricted audience boundary. A plugin must not be
        // able to register a definition with an exact `KNOWN_USER` /
        // `OPERATOR` name (e.g. `chaffra.analysis.findings_total` with
        // attacker-controlled `description`/`unit`/`kind`) and have it cross
        // `user-only` solely because the name classifies as user-facing.
        // TODO(#45): derive audience server-side here from a trusted
        // `(module_id, name)` registry instead of name-level provenance.
        self.collector
            .register_untrusted_metrics(&req.module_id, definitions)
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(
            chaffra_proto::proto::RegisterMetricsResponse { success: true },
        ))
    }

    async fn record_metrics(
        &self,
        request: tonic::Request<chaffra_proto::proto::RecordMetricsRequest>,
    ) -> std::result::Result<
        tonic::Response<chaffra_proto::proto::RecordMetricsResponse>,
        tonic::Status,
    > {
        let req = request.into_inner();
        let points: Vec<_> = req.data_points.iter().map(data_point_from_proto).collect();
        let count = points.len() as u64;
        // External module submissions are UNTRUSTED: route them through the
        // provenance-tracking ingress so the snapshot projection fails them
        // closed at every restricted audience boundary. A plugin must not be
        // able to cross `user-only` / `operator-only` by naming its metric
        // after a trusted user-facing or operator metric.
        // TODO(#45): derive audience server-side here from a trusted
        // `(module_id, name)` registry instead of name-level provenance.
        self.collector.record_untrusted_data_points(points);
        Ok(tonic::Response::new(
            chaffra_proto::proto::RecordMetricsResponse { accepted: count },
        ))
    }

    async fn record_span(
        &self,
        request: tonic::Request<chaffra_proto::proto::RecordSpanRequest>,
    ) -> std::result::Result<tonic::Response<chaffra_proto::proto::RecordSpanResponse>, tonic::Status>
    {
        let req = request.into_inner();
        let spans: Vec<_> = req.spans.iter().map(span_from_proto).collect();
        let count = spans.len() as u64;
        self.collector.record_spans(spans);
        Ok(tonic::Response::new(
            chaffra_proto::proto::RecordSpanResponse { accepted: count },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TelemetryConfig;
    use chaffra_proto::proto;
    use chaffra_proto::proto::telemetry_collector_server::TelemetryCollector as TelemetryCollectorTrait;
    use std::collections::HashMap;

    fn make_service() -> TelemetryGrpcService {
        let collector = TelemetryCollector::new(TelemetryConfig::default());
        TelemetryGrpcService::new(collector)
    }

    #[tokio::test]
    async fn test_register_metrics() {
        let service = make_service();
        let request = tonic::Request::new(proto::RegisterMetricsRequest {
            module_id: "test".to_owned(),
            definitions: vec![proto::MetricDefinition {
                name: "test.counter".to_owned(),
                kind: 1, // COUNTER
                description: "A test counter".to_owned(),
                unit: "count".to_owned(),
            }],
        });

        let response = service.register_metrics(request).await.unwrap();
        assert!(response.into_inner().success);
    }

    #[tokio::test]
    async fn test_record_metrics() {
        let service = make_service();
        let request = tonic::Request::new(proto::RecordMetricsRequest {
            module_id: "test".to_owned(),
            data_points: vec![proto::MetricDataPoint {
                name: "test.metric".to_owned(),
                value: 42.0,
                labels: HashMap::new(),
                timestamp_ms: 1000,
            }],
        });

        let response = service.record_metrics(request).await.unwrap();
        assert_eq!(response.into_inner().accepted, 1);
    }

    #[tokio::test]
    async fn test_record_span() {
        let service = make_service();
        let request = tonic::Request::new(proto::RecordSpanRequest {
            module_id: "test".to_owned(),
            spans: vec![proto::SpanData {
                name: "analyze".to_owned(),
                trace_id: "t1".to_owned(),
                span_id: "s1".to_owned(),
                parent_span_id: String::new(),
                start_time_ms: 100,
                end_time_ms: 200,
                attributes: HashMap::new(),
                status: "ok".to_owned(),
            }],
        });

        let response = service.record_span(request).await.unwrap();
        assert_eq!(response.into_inner().accepted, 1);
    }
}
