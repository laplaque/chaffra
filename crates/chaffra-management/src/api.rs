use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::server::SharedState;

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub files_total: u64,
    pub analysis_duration_ms: u64,
    pub data_points: Vec<DataPointEntry>,
    pub backends: Vec<BackendStatusEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DataPointEntry {
    pub name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackendStatusEntry {
    pub name: String,
    pub kind: String,
    pub connected: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsHistoryResponse {
    pub window: String,
    pub snapshots: Vec<serde_json::Value>,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModulesResponse {
    pub modules: Vec<ModuleEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub id: String,
    pub status: String,
    pub finding_count: u64,
    pub duration_ms: u64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingsSummaryResponse {
    pub total: u64,
    pub by_module: HashMap<String, u64>,
    pub by_severity: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FindingsChurnResponse {
    pub new_count: u64,
    pub resolved_count: u64,
    pub unchanged_count: u64,
    pub churn_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub score: Option<f64>,
    pub grade: String,
    pub files: Vec<FileHealthEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileHealthEntry {
    pub file: String,
    pub score: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub audience: String,
    pub sampling_rate: f64,
    pub sampling_strategy: String,
    pub backends: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_window")]
    pub window: String,
    pub module: Option<String>,
    pub severity: Option<String>,
    pub metric: Option<String>,
}

fn default_window() -> String {
    "7d".to_owned()
}

pub async fn get_metrics(state: axum::extract::State<Arc<SharedState>>) -> Json<MetricsResponse> {
    let (_, statuses) =
        chaffra_telemetry::backends::create_backends(&state.collector.config().backends);
    let backends = statuses
        .into_iter()
        .map(|s| BackendStatusEntry {
            name: s.name,
            kind: s.kind,
            connected: s.connected,
            message: s.message,
        })
        .collect();

    let Some(raw_snapshot) = state.live_state.current() else {
        return Json(MetricsResponse {
            files_total: 0,
            analysis_duration_ms: 0,
            data_points: Vec::new(),
            backends,
        });
    };
    let snapshot = if state.audience.operator_enabled() {
        raw_snapshot
    } else {
        raw_snapshot.user_scoped()
    };
    let data_points = snapshot
        .data_points
        .iter()
        .map(|dp| DataPointEntry {
            name: dp.name.clone(),
            value: dp.value,
            labels: dp.labels.clone(),
        })
        .collect();

    Json(MetricsResponse {
        files_total: snapshot.user_summary.files_total,
        analysis_duration_ms: snapshot.user_summary.analysis_duration_ms,
        data_points,
        backends,
    })
}

pub async fn get_metrics_history(
    state: axum::extract::State<Arc<SharedState>>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> Json<MetricsHistoryResponse> {
    let source = state.live_state.source();
    let (status, message) = match source {
        chaffra_telemetry::StateSource::Live => (
            "live".to_owned(),
            "Live telemetry data from analysis runs.".to_owned(),
        ),
        chaffra_telemetry::StateSource::Seeded => (
            "seeded".to_owned(),
            "Seeded demo/test data. Run an analysis to populate live metrics.".to_owned(),
        ),
        chaffra_telemetry::StateSource::Empty => {
            return Json(MetricsHistoryResponse {
                window: query.window,
                snapshots: Vec::new(),
                status: "empty".to_owned(),
                message: "No telemetry data available. Start the management server with seeded data, or run an analysis with a co-located management server.".to_owned(),
            });
        }
    };

    let snapshots = if let Some(ref module) = query.module {
        state.live_state.history_by_module(module, &query.window)
    } else if let Some(ref severity) = query.severity {
        state
            .live_state
            .history_by_severity(severity, &query.window)
    } else if let Some(ref metric) = query.metric {
        state.live_state.history_by_metric(metric, &query.window)
    } else {
        state.live_state.history_window(&query.window)
    };
    let include_operator = state.audience.operator_enabled();
    let snapshot_values: Vec<serde_json::Value> = snapshots
        .iter()
        .map(|s| {
            if include_operator {
                s.clone()
            } else {
                s.user_scoped()
            }
        })
        .filter_map(|s| serde_json::to_value(&s).ok())
        .collect();

    Json(MetricsHistoryResponse {
        window: query.window,
        snapshots: snapshot_values,
        status,
        message,
    })
}

pub async fn get_modules(state: axum::extract::State<Arc<SharedState>>) -> Json<ModulesResponse> {
    let Some(snapshot) = state.live_state.current() else {
        return Json(ModulesResponse {
            modules: Vec::new(),
        });
    };
    let include_operator = state.audience.operator_enabled();
    let modules = snapshot
        .user_summary
        .module_summaries
        .iter()
        .map(|(id, summary)| {
            let has_error = include_operator
                && snapshot
                    .operator_summary
                    .module_error_counts
                    .get(id)
                    .copied()
                    .unwrap_or(0)
                    > 0;
            ModuleEntry {
                id: id.clone(),
                status: if has_error {
                    "error".to_owned()
                } else {
                    "healthy".to_owned()
                },
                finding_count: summary.finding_count,
                duration_ms: summary.duration_ms,
                capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            }
        })
        .collect();

    Json(ModulesResponse { modules })
}

pub async fn get_findings_summary(
    state: axum::extract::State<Arc<SharedState>>,
) -> Json<FindingsSummaryResponse> {
    let Some(snapshot) = state.live_state.current() else {
        return Json(FindingsSummaryResponse {
            total: 0,
            by_module: HashMap::new(),
            by_severity: HashMap::new(),
        });
    };
    let total = snapshot
        .user_summary
        .findings_by_module
        .values()
        .sum::<u64>();

    Json(FindingsSummaryResponse {
        total,
        by_module: snapshot.user_summary.findings_by_module.clone(),
        by_severity: snapshot.user_summary.findings_by_severity.clone(),
    })
}

pub async fn get_findings_churn(
    state: axum::extract::State<Arc<SharedState>>,
) -> Json<FindingsChurnResponse> {
    let Some(snapshot) = state.live_state.current() else {
        return Json(FindingsChurnResponse {
            new_count: 0,
            resolved_count: 0,
            unchanged_count: 0,
            churn_rate: 0.0,
        });
    };
    let churn_new = snapshot
        .data_points
        .iter()
        .find(|p| p.name == "chaffra.findings.new")
        .map(|p| p.value as u64)
        .unwrap_or(0);
    let churn_resolved = snapshot
        .data_points
        .iter()
        .find(|p| p.name == "chaffra.findings.resolved")
        .map(|p| p.value as u64)
        .unwrap_or(0);
    let churn_unchanged = snapshot
        .data_points
        .iter()
        .find(|p| p.name == "chaffra.findings.unchanged")
        .map(|p| p.value as u64)
        .unwrap_or(0);
    let churn_rate = snapshot
        .data_points
        .iter()
        .find(|p| p.name == "chaffra.findings.churn_rate")
        .map(|p| p.value)
        .unwrap_or(0.0);

    Json(FindingsChurnResponse {
        new_count: churn_new,
        resolved_count: churn_resolved,
        unchanged_count: churn_unchanged,
        churn_rate,
    })
}

pub async fn get_health(state: axum::extract::State<Arc<SharedState>>) -> Json<HealthResponse> {
    let Some(snapshot) = state.live_state.current() else {
        return Json(HealthResponse {
            score: None,
            grade: "\u{2014}".to_owned(),
            files: Vec::new(),
        });
    };
    let health_scores: Vec<f64> = snapshot
        .data_points
        .iter()
        .filter(|p| p.name.starts_with("chaffra.module.") && p.name.ends_with(".health_score"))
        .map(|p| p.value)
        .collect();
    let score = if health_scores.is_empty() {
        None
    } else {
        Some(health_scores.iter().sum::<f64>() / health_scores.len() as f64)
    };

    let grade = match score {
        Some(s) if s >= 90.0 => "A",
        Some(s) if s >= 80.0 => "B",
        Some(s) if s >= 70.0 => "C",
        Some(s) if s >= 60.0 => "D",
        Some(_) => "F",
        None => "—",
    };

    Json(HealthResponse {
        score,
        grade: grade.to_owned(),
        files: Vec::new(),
    })
}

pub async fn get_config(state: axum::extract::State<Arc<SharedState>>) -> Json<ConfigResponse> {
    let config = state.collector.config();

    let audience = serde_json::to_value(config.audience)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", config.audience));
    let sampling_strategy = serde_json::to_value(config.sampling_strategy)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", config.sampling_strategy));

    Json(ConfigResponse {
        audience,
        sampling_rate: config.sampling_rate,
        sampling_strategy,
        backends: config
            .backends
            .iter()
            .map(|b| {
                serde_json::to_value(&b.kind)
                    .ok()
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| format!("{:?}", b.kind))
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_window() {
        assert_eq!(default_window(), "7d");
    }

    #[test]
    fn test_response_serialization() {
        let resp = FindingsChurnResponse {
            new_count: 3,
            resolved_count: 1,
            unchanged_count: 10,
            churn_rate: 0.23,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: FindingsChurnResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.new_count, 3);
    }

    #[test]
    fn test_history_query_deserialize_with_filters() {
        let json = r#"{"window":"1h","module":"dead-code"}"#;
        let q: HistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.window, "1h");
        assert_eq!(q.module.as_deref(), Some("dead-code"));
        assert!(q.severity.is_none());
        assert!(q.metric.is_none());
    }

    #[test]
    fn test_history_query_deserialize_severity() {
        let json = r#"{"severity":"warning"}"#;
        let q: HistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.window, "7d");
        assert_eq!(q.severity.as_deref(), Some("warning"));
    }

    #[test]
    fn test_history_query_deserialize_metric() {
        let json = r#"{"metric":"chaffra.module.call_duration_ms"}"#;
        let q: HistoryQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.metric.as_deref(), Some("chaffra.module.call_duration_ms"));
    }
}
