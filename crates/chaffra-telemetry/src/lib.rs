//! Telemetry collection, aggregation, and backend sinks for chaffra analysis.
//!
//! Implements the `TelemetryCollector` gRPC service. Receives metrics from all
//! modules, aggregates them, and sinks to configurable backends (JSON file,
//! stderr, Prometheus, OTLP, StatsD, CloudWatch).
//!
//! Two telemetry audiences:
//! - **User-facing**: analysis duration, finding counts, health scores (included in output).
//! - **Operator**: call latencies, error rates, memory pressure (sunk to backends).

pub mod audit_log;
pub mod backends;
pub mod cache_metrics;
pub mod churn;
pub mod collector;
pub mod config;
pub mod dashboard;
pub mod error;
pub mod grpc_service;
pub mod lifecycle;
pub mod live_state;
pub mod metrics;
pub mod module;
pub mod sampling;
pub mod seed;

pub use collector::TelemetryCollector;
pub use config::{BackendConfig, BackendKind, TelemetryAudience, TelemetryConfig};
pub use error::TelemetryError;
pub use lifecycle::{
    FinalizeResult, finalize_and_flush, finalize_and_flush_sampled, flush_snapshot,
};
pub use live_state::{LiveTelemetryState, StateSource};
pub use metrics::{MetricDataPoint, MetricDefinition, MetricKind, SpanData};
pub use module::TelemetryModule;
pub use sampling::{SamplingDecision, SamplingStrategy};
