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
    async fn test_health_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/api/v1/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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
    }
}
