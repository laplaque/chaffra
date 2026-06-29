use axum::Router;
use axum::response::Html;
use axum::routing::get;
use std::sync::Arc;

use crate::api;
use crate::dashboard_html::DASHBOARD_HTML;

pub struct SharedState {
    pub collector: chaffra_telemetry::TelemetryCollector,
}

#[derive(Debug, Clone)]
pub struct ManagementConfig {
    pub port: u16,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self { port: 9100 }
    }
}

pub struct ManagementServer {
    config: ManagementConfig,
    state: Arc<SharedState>,
}

impl ManagementServer {
    pub fn new(config: ManagementConfig, collector: chaffra_telemetry::TelemetryCollector) -> Self {
        Self {
            config,
            state: Arc::new(SharedState { collector }),
        }
    }

    pub fn router(&self) -> Router {
        build_router(self.state.clone())
    }

    pub async fn run(self) -> Result<(), std::io::Error> {
        let addr = format!("127.0.0.1:{}", self.config.port);
        let router = build_router(self.state);

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        eprintln!("Management dashboard: http://{addr}");
        eprintln!("REST API: http://{addr}/api/v1/");
        axum::serve(listener, router).await
    }
}

fn build_router(state: Arc<SharedState>) -> Router {
    Router::new()
        .route("/", get(dashboard_handler))
        .route("/api/v1/metrics", get(api::get_metrics))
        .route("/api/v1/metrics/history", get(api::get_metrics_history))
        .route("/api/v1/modules", get(api::get_modules))
        .route("/api/v1/findings/summary", get(api::get_findings_summary))
        .route("/api/v1/findings/churn", get(api::get_findings_churn))
        .route("/api/v1/health", get(api::get_health))
        .route("/api/v1/config", get(api::get_config))
        .with_state(state)
}

async fn dashboard_handler() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> Arc<SharedState> {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.set_files_total(42);
        collector.record_module_call("dead-code", 150, false);
        collector.record_module_findings(
            "dead-code",
            5,
            &[("warning".to_owned(), 3), ("info".to_owned(), 2)]
                .into_iter()
                .collect(),
        );
        Arc::new(SharedState { collector })
    }

    #[tokio::test]
    async fn test_dashboard_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Chaffra Management Dashboard"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["files_total"], 42);
    }

    #[tokio::test]
    async fn test_modules_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/modules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let modules = parsed["modules"].as_array().unwrap();
        assert!(!modules.is_empty());
    }

    #[tokio::test]
    async fn test_findings_summary_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::get("/api/v1/findings/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["total"], 5);
    }

    #[tokio::test]
    async fn test_findings_churn_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::get("/api/v1/findings/churn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_findings_churn_returns_real_values() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let churn = chaffra_telemetry::churn::ChurnResult {
            new_count: 3,
            resolved_count: 1,
            unchanged_count: 8,
            churn_rate: 0.27,
        };
        collector.record_finding_churn(&churn);

        let state = Arc::new(SharedState { collector });
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::get("/api/v1/findings/churn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["new_count"], 3);
        assert_eq!(parsed["resolved_count"], 1);
        assert_eq!(parsed["unchanged_count"], 8);
        assert!((parsed["churn_rate"].as_f64().unwrap() - 0.27).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint_with_module_score() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.record_module_summary_metric("complexity", "health_score", 85.0);

        let state = Arc::new(SharedState { collector });
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["score"], 85.0);
        assert_eq!(parsed["grade"], "B");
    }

    #[tokio::test]
    async fn test_config_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["audience"].is_string());
    }

    /// A collector whose telemetry config opts into the operator audience and
    /// carries an OTLP backend, for asserting the operator-gated metadata is
    /// disclosed only under an operator audience (R10-F2).
    fn operator_state() -> Arc<SharedState> {
        let config = chaffra_telemetry::TelemetryConfig {
            audience: chaffra_telemetry::TelemetryAudience::On,
            backends: vec![chaffra_telemetry::BackendConfig {
                kind: chaffra_telemetry::BackendKind::Otlp,
                endpoint: Some("http://operator-host:4317".to_owned()),
                path: None,
                options: std::collections::HashMap::new(),
            }],
            ..Default::default()
        };
        Arc::new(SharedState {
            collector: chaffra_telemetry::TelemetryCollector::new(config),
        })
    }

    #[tokio::test]
    async fn test_metrics_backends_empty_under_user_only() {
        // R10-F2: the default `user-only` audience must not disclose
        // operator-shaped backend status metadata.
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed["backends"].as_array().unwrap().is_empty(),
            "backend status must be withheld under user-only: {parsed}"
        );
    }

    #[tokio::test]
    async fn test_metrics_backends_populated_under_operator() {
        // R10-F2: an operator-enabled audience discloses backend status.
        let app = build_router(operator_state());
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let backends = parsed["backends"].as_array().unwrap();
        assert_eq!(
            backends.len(),
            1,
            "operator audience discloses backend status"
        );
        assert_eq!(backends[0]["kind"], "Otlp");
        assert!(backends[0]["name"].is_string());
        assert!(backends[0].get("connected").is_some());
        assert!(backends[0].get("message").is_some());
    }

    #[tokio::test]
    async fn test_config_backends_empty_under_user_only() {
        // R10-F2: backend kinds are operator metadata, withheld under user-only.
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed["backends"].as_array().unwrap().is_empty(),
            "backend kinds must be withheld under user-only: {parsed}"
        );
        // The non-operator config fields are still disclosed.
        assert!(parsed["audience"].is_string());
    }

    #[tokio::test]
    async fn test_config_backends_populated_under_operator() {
        // R10-F2: an operator-enabled audience discloses backend kinds.
        let app = build_router(operator_state());
        let resp = app
            .oneshot(Request::get("/api/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let backends = parsed["backends"].as_array().unwrap();
        assert_eq!(
            backends.len(),
            1,
            "operator audience discloses backend kinds"
        );
        assert_eq!(backends[0], "Otlp");
    }

    #[tokio::test]
    async fn test_config_sampling_withheld_under_user_only() {
        // R13: sampling_rate / sampling_strategy describe the operator-telemetry
        // emission policy (operator-shaped config metadata, like backends), so
        // they must be withheld (null) under the default user-only audience.
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed["sampling_rate"].is_null(),
            "sampling_rate must be withheld under user-only: {parsed}"
        );
        assert!(
            parsed["sampling_strategy"].is_null(),
            "sampling_strategy must be withheld under user-only: {parsed}"
        );
        // The user-facing audience mode is still reported.
        assert!(parsed["audience"].is_string());
    }

    #[tokio::test]
    async fn test_config_sampling_disclosed_under_operator() {
        // Under an operator-enabled audience the sampling policy IS disclosed.
        let app = build_router(operator_state());
        let resp = app
            .oneshot(Request::get("/api/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed["sampling_rate"].as_f64().is_some(),
            "sampling_rate must be present under an operator audience: {parsed}"
        );
        assert!(
            parsed["sampling_strategy"].is_string(),
            "sampling_strategy must be present under an operator audience: {parsed}"
        );
    }

    /// A collector at the given audience that has recorded an operator metric
    /// (per-module call duration) and a module error — the operator-shaped data
    /// the management projection must scrub under `user-only`.
    fn state_with_operator_data(
        audience: chaffra_telemetry::TelemetryAudience,
    ) -> Arc<SharedState> {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience,
                ..Default::default()
            });
        // "failing" ran with a 250ms call and an error; give it a finding so the
        // module entry is retained under user-only (payload-empty modules are
        // dropped) and we can assert the operator FIELDS are scrubbed.
        collector.record_module_call("failing", 250, true);
        collector.record_module_findings(
            "failing",
            1,
            &[("warning".to_owned(), 1)].into_iter().collect(),
        );
        Arc::new(SharedState { collector })
    }

    #[tokio::test]
    async fn test_metrics_data_points_scrubbed_under_user_only() {
        // R10 round-11: the management /metrics output is audience-projected, so
        // the operator data point chaffra.module.call_duration_ms must NOT appear
        // under the default user-only audience.
        let app = build_router(state_with_operator_data(
            chaffra_telemetry::TelemetryAudience::UserOnly,
        ));
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = parsed["data_points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n.contains("call_duration_ms") || n.contains("error_total")),
            "operator data points must be scrubbed under user-only: {names:?}"
        );
    }

    #[tokio::test]
    async fn test_metrics_data_points_present_under_operator() {
        // Under an operator audience the same operator data point IS disclosed.
        let app = build_router(state_with_operator_data(
            chaffra_telemetry::TelemetryAudience::On,
        ));
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let names: Vec<&str> = parsed["data_points"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(
            names.iter().any(|n| n.contains("call_duration_ms")),
            "operator data points must be present under an operator audience: {names:?}"
        );
    }

    #[tokio::test]
    async fn test_modules_operator_fields_scrubbed_under_user_only() {
        // R10 round-11: per-module duration_ms (the operator call_duration_ms)
        // and the error-derived status read operator-shaped fields, so under
        // user-only the projection zeroes the duration and empties the error
        // counts → status "healthy".
        let app = build_router(state_with_operator_data(
            chaffra_telemetry::TelemetryAudience::UserOnly,
        ));
        let resp = app
            .oneshot(Request::get("/api/v1/modules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let m = parsed["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "failing")
            .expect("module retained (has a finding) but with operator fields scrubbed");
        assert_eq!(
            m["duration_ms"], 0,
            "per-module duration must be scrubbed under user-only"
        );
        assert_eq!(
            m["status"], "healthy",
            "error status must be withheld under user-only"
        );
    }

    #[tokio::test]
    async fn test_modules_operator_fields_shown_under_operator() {
        // Under an operator audience the duration and error status ARE disclosed.
        let app = build_router(state_with_operator_data(
            chaffra_telemetry::TelemetryAudience::On,
        ));
        let resp = app
            .oneshot(Request::get("/api/v1/modules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let m = parsed["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["id"] == "failing")
            .expect("module present under operator audience");
        assert_eq!(m["duration_ms"], 250);
        assert_eq!(m["status"], "error");
    }

    #[tokio::test]
    async fn test_metrics_history_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::get("/api/v1/metrics/history?window=7d")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["window"], "7d");
        assert_eq!(parsed["status"], "not_implemented");
        assert!(parsed["message"].as_str().unwrap().contains("co-located"));
        assert!(parsed["snapshots"].as_array().unwrap().is_empty());
    }
}
