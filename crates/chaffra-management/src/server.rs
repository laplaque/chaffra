use axum::Router;
use axum::response::Html;
use axum::routing::get;
use std::sync::Arc;

use crate::api;
use crate::dashboard_html::DASHBOARD_HTML;

pub struct SharedState {
    pub collector: chaffra_telemetry::TelemetryCollector,
    pub live_state: chaffra_telemetry::LiveTelemetryState,
}

impl SharedState {
    pub fn audience(&self) -> chaffra_telemetry::config::TelemetryAudience {
        self.collector.config().audience
    }
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
    pub fn new(
        config: ManagementConfig,
        collector: chaffra_telemetry::TelemetryCollector,
        live_state: chaffra_telemetry::LiveTelemetryState,
    ) -> Self {
        Self {
            config,
            state: Arc::new(SharedState {
                collector,
                live_state,
            }),
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
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        Arc::new(SharedState {
            collector,
            live_state,
        })
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

        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
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

        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
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

    #[tokio::test]
    async fn test_metrics_history_endpoint_empty() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        assert_eq!(parsed["status"], "empty");
        assert!(
            parsed["message"]
                .as_str()
                .unwrap()
                .contains("No telemetry data")
        );
        assert!(parsed["snapshots"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_metrics_history_endpoint_seeded() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let live_state = chaffra_telemetry::seed::seed_live_state();
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        assert_eq!(parsed["status"], "seeded");
        let snapshots = parsed["snapshots"].as_array().unwrap();
        assert!(
            snapshots.len() >= 10,
            "seeded history should have 10+ snapshots, got {}",
            snapshots.len()
        );
    }

    #[tokio::test]
    async fn test_metrics_history_live_source() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.set_files_total(10);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        assert_eq!(parsed["status"], "live");
        assert_eq!(parsed["snapshots"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_metrics_history_operator_audience() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::On,
                ..Default::default()
            });
        let live_state = chaffra_telemetry::seed::seed_live_state();
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        let snapshots = parsed["snapshots"].as_array().unwrap();
        assert!(!snapshots.is_empty());
        let first = &snapshots[0];
        assert!(first.get("operator_summary").is_some());
    }

    #[tokio::test]
    async fn test_management_server_constructor_and_router() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        let config = ManagementConfig { port: 0 };
        let server = ManagementServer::new(config, collector, live_state);
        let app = server.router();
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_user_only_hides_operator_datapoints() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.record_module_call("dead-code", 150, false);
        collector.set_files_total(10);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let dps = parsed["data_points"].as_array().unwrap();
        for dp in dps {
            let name = dp["name"].as_str().unwrap();
            assert!(
                !name.starts_with("chaffra.module.call_duration"),
                "operator datapoint {name} leaked through UserOnly metrics endpoint"
            );
            assert!(
                !name.starts_with("chaffra.module.error_total"),
                "operator datapoint {name} leaked through UserOnly metrics endpoint"
            );
        }
    }

    #[tokio::test]
    async fn test_metrics_endpoint_operator_includes_all_datapoints() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::On,
                ..Default::default()
            });
        collector.record_module_call("dead-code", 150, false);
        collector.set_files_total(10);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
        let resp = app
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let dps = parsed["data_points"].as_array().unwrap();
        let has_call_duration = dps
            .iter()
            .any(|dp| dp["name"].as_str().unwrap().contains("call_duration"));
        assert!(
            has_call_duration,
            "operator audience should include call_duration datapoints"
        );
    }

    #[tokio::test]
    async fn test_modules_user_only_hides_operator_error_status() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.record_module_call("dead-code", 150, true);
        collector.set_files_total(1);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        for m in modules {
            assert_eq!(
                m["status"].as_str().unwrap(),
                "healthy",
                "UserOnly should not expose operator error status"
            );
        }
    }

    #[tokio::test]
    async fn test_modules_operator_shows_error_status() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::On,
                ..Default::default()
            });
        collector.record_module_call("dead-code", 150, true);
        collector.set_files_total(1);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        let dc = modules.iter().find(|m| m["id"] == "dead-code").unwrap();
        assert_eq!(
            dc["status"].as_str().unwrap(),
            "error",
            "Operator audience should expose error status from module_error_counts"
        );
    }

    #[tokio::test]
    async fn test_config_returns_kebab_case_values() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/config").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["audience"].as_str().unwrap(),
            "user-only",
            "audience should be kebab-case"
        );
        assert_eq!(
            parsed["sampling_strategy"].as_str().unwrap(),
            "rate",
            "sampling_strategy should be kebab-case"
        );
        let backends = parsed["backends"].as_array().unwrap();
        assert!(
            backends.iter().all(|b| b.as_str().unwrap() == "json-file"),
            "backend kinds should be kebab-case"
        );
    }

    #[tokio::test]
    async fn test_seeded_management_populates_all_endpoints() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let live_state = chaffra_telemetry::seed::seed_live_state();
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/metrics/history?window=7d")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let history: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(history["status"].as_str().unwrap(), "seeded");
        assert!(
            !history["snapshots"].as_array().unwrap().is_empty(),
            "history should have seeded snapshots"
        );

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let metrics: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            metrics["files_total"].as_u64().unwrap() > 0,
            "seeded metrics should have populated files_total"
        );
        assert!(
            !metrics["data_points"].as_array().unwrap().is_empty(),
            "seeded metrics should have data_points"
        );

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/modules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let modules: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !modules["modules"].as_array().unwrap().is_empty(),
            "seeded modules should be populated"
        );

        let resp = app
            .oneshot(
                Request::get("/api/v1/findings/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let findings: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            findings["total"].as_u64().unwrap() > 0,
            "seeded findings summary should have non-zero total"
        );
    }

    #[tokio::test]
    async fn test_empty_live_state_returns_defaults() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let metrics: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(metrics["files_total"], 0);
        assert!(metrics["data_points"].as_array().unwrap().is_empty());

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/modules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let modules: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(modules["modules"].as_array().unwrap().is_empty());

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/findings/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let findings: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(findings["total"], 0);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/findings/churn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let churn: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(churn["new_count"], 0);
        assert_eq!(churn["churn_rate"], 0.0);

        let resp = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(health["score"].is_null());
    }

    #[tokio::test]
    async fn test_history_filter_by_module() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::On,
                ..Default::default()
            });
        collector.set_files_total(20);
        collector.record_module_call("dead-code", 150, false);
        collector.record_module_findings(
            "dead-code",
            5,
            &[("warning".to_owned(), 3), ("info".to_owned(), 2)]
                .into_iter()
                .collect(),
        );
        collector.record_module_call("complexity", 80, false);
        collector.record_module_findings(
            "complexity",
            2,
            &[("info".to_owned(), 2)].into_iter().collect(),
        );

        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::get("/api/v1/metrics/history?module=dead-code")
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
        assert_eq!(parsed["status"], "live");
        let snapshots = parsed["snapshots"].as_array().unwrap();
        assert_eq!(snapshots.len(), 1);
        // Verify snapshot contains the dead-code module in its user_summary
        let snap = &snapshots[0];
        let modules = snap["user_summary"]["module_summaries"]
            .as_object()
            .unwrap();
        assert!(
            modules.contains_key("dead-code"),
            "filtered snapshot should contain dead-code module"
        );
    }

    #[tokio::test]
    async fn test_history_filter_by_severity() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 100, false);
        collector.record_module_findings(
            "dead-code",
            5,
            &[("warning".to_owned(), 3), ("info".to_owned(), 2)]
                .into_iter()
                .collect(),
        );

        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::get("/api/v1/metrics/history?severity=warning")
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
        assert_eq!(parsed["status"], "live");
        let snapshots = parsed["snapshots"].as_array().unwrap();
        assert_eq!(
            snapshots.len(),
            1,
            "should return 1 snapshot matching severity=warning"
        );
        // Verify findings_by_severity contains warning
        let snap = &snapshots[0];
        let sev = snap["user_summary"]["findings_by_severity"]
            .as_object()
            .unwrap();
        assert!(
            sev.contains_key("warning"),
            "filtered snapshot should have warning severity"
        );
        assert_eq!(sev["warning"], 3);
    }

    #[tokio::test]
    async fn test_history_filter_by_metric() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::On,
                ..Default::default()
            });
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 150, false);

        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
        let resp = app
            .oneshot(
                Request::get("/api/v1/metrics/history?metric=chaffra.module.call_duration_ms")
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
        assert_eq!(parsed["status"], "live");
        let snapshots = parsed["snapshots"].as_array().unwrap();
        assert_eq!(
            snapshots.len(),
            1,
            "should return 1 snapshot matching metric=chaffra.module.call_duration_ms"
        );
        // Verify data_points contain the metric
        let snap = &snapshots[0];
        let dps = snap["data_points"].as_array().unwrap();
        let has_metric = dps.iter().any(|dp| {
            dp["name"]
                .as_str()
                .unwrap()
                .starts_with("chaffra.module.call_duration_ms")
        });
        assert!(
            has_metric,
            "filtered snapshot should contain chaffra.module.call_duration_ms data point"
        );
    }

    #[tokio::test]
    async fn test_live_snapshot_feeds_all_endpoints() {
        let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
        collector.set_files_total(50);
        collector.record_module_call("complexity", 200, false);
        collector.record_module_findings(
            "complexity",
            7,
            &[("warning".to_owned(), 4), ("info".to_owned(), 3)]
                .into_iter()
                .collect(),
        );
        collector.record_module_summary_metric("complexity", "health_score", 88.0);
        let churn = chaffra_telemetry::churn::ChurnResult {
            new_count: 2,
            resolved_count: 1,
            unchanged_count: 4,
            churn_rate: 0.33,
        };
        collector.record_finding_churn(&churn);

        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let metrics: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(metrics["files_total"], 50);

        let resp = app
            .clone()
            .oneshot(Request::get("/api/v1/modules").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let modules: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let mods = modules["modules"].as_array().unwrap();
        assert_eq!(mods.len(), 1);
        assert_eq!(mods[0]["id"], "complexity");

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/findings/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let findings: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(findings["total"], 7);

        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/findings/churn")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let churn_resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(churn_resp["new_count"], 2);

        let resp = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(health["score"], 88.0);
        assert_eq!(health["grade"], "B");
    }

    #[tokio::test]
    async fn test_modules_off_audience_returns_empty() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::Off,
                ..Default::default()
            });
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 100, false);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
        let app = build_router(state);
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
        assert!(
            modules.is_empty(),
            "Off audience should return empty modules list"
        );
    }

    #[tokio::test]
    async fn test_findings_churn_off_audience_returns_zeros() {
        let collector =
            chaffra_telemetry::TelemetryCollector::new(chaffra_telemetry::TelemetryConfig {
                audience: chaffra_telemetry::config::TelemetryAudience::Off,
                ..Default::default()
            });
        let churn = chaffra_telemetry::churn::ChurnResult {
            new_count: 5,
            resolved_count: 2,
            unchanged_count: 10,
            churn_rate: 0.29,
        };
        collector.record_finding_churn(&churn);
        let live_state = chaffra_telemetry::LiveTelemetryState::new();
        live_state.push_snapshot(collector.snapshot());
        let state = Arc::new(SharedState {
            collector,
            live_state,
        });
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
        assert_eq!(
            parsed["new_count"], 0,
            "Off audience should zero out churn data"
        );
        assert_eq!(parsed["resolved_count"], 0);
        assert_eq!(parsed["unchanged_count"], 0);
        assert_eq!(parsed["churn_rate"], 0.0);
    }
}
