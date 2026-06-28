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
    /// Operator-shaped: the operator-telemetry sampling policy. `None`
    /// (serialized as `null`) when the resolved audience is not operator-enabled
    /// (R13). Populated only under `on` / `operator-only`.
    pub sampling_rate: Option<f64>,
    pub sampling_strategy: Option<String>,
    pub backends: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_window")]
    pub window: String,
}

fn default_window() -> String {
    "7d".to_owned()
}

pub async fn get_metrics(state: axum::extract::State<Arc<SharedState>>) -> Json<MetricsResponse> {
    let audience = state.collector.config().audience;
    // The management dashboard is an output boundary like the CLI, MCP, and
    // backend-flush paths, so it must project the snapshot through the resolved
    // audience before disclosing it. Reusing the audited type-level guard
    // (`project_for_audience`) — rather than a hand-rolled per-field filter —
    // scrubs operator-shaped payload (operator `data_points`, per-module timing)
    // under the default `user-only`, with no risk of the projection logic and a
    // bespoke management filter drifting apart. The remaining co-located
    // live-collector / history integration is Stage 15a.3; the audience gate on
    // the standalone outputs is enforced here now.
    let snapshot = state.collector.snapshot().project_for_audience(audience);
    let data_points = snapshot
        .data_points
        .iter()
        .map(|dp| DataPointEntry {
            name: dp.name.clone(),
            value: dp.value,
            labels: dp.labels.clone(),
        })
        .collect();

    // R10-F2: backend kind / endpoint / connectivity is operator-shaped
    // config/status *metadata* (not part of the snapshot payload), so it carries
    // its own audience gate. The management collector is built from the CLI
    // telemetry config (default `user-only`), so disclose backend status only
    // when the operator audience is opted in; otherwise return an empty list.
    let backends = if audience.operator_enabled() {
        let (_, statuses) =
            chaffra_telemetry::backends::create_backends(&state.collector.config().backends);
        statuses
            .into_iter()
            .map(|s| BackendStatusEntry {
                name: s.name,
                kind: s.kind,
                connected: s.connected,
                message: s.message,
            })
            .collect()
    } else {
        Vec::new()
    };

    Json(MetricsResponse {
        files_total: snapshot.user_summary.files_total,
        analysis_duration_ms: snapshot.user_summary.analysis_duration_ms,
        data_points,
        backends,
    })
}

pub async fn get_metrics_history(
    _state: axum::extract::State<Arc<SharedState>>,
    axum::extract::Query(query): axum::extract::Query<HistoryQuery>,
) -> Json<MetricsHistoryResponse> {
    Json(MetricsHistoryResponse {
        window: query.window,
        snapshots: Vec::new(),
        status: "not_implemented".to_owned(),
        message: "Time-series history requires the streaming/watch mode integration. This endpoint will return snapshots once co-located mode is available.".to_owned(),
    })
}

pub async fn get_modules(state: axum::extract::State<Arc<SharedState>>) -> Json<ModulesResponse> {
    // Project so operator-shaped fields are scrubbed under `user-only`: the
    // per-module `duration_ms` is the operator `chaffra.module.call_duration_ms`
    // (zeroed by projection), and the error-derived `status` reads
    // `operator_summary.module_error_counts` (emptied by projection → "healthy").
    let audience = state.collector.config().audience;
    let snapshot = state.collector.snapshot().project_for_audience(audience);
    let modules = snapshot
        .user_summary
        .module_summaries
        .iter()
        .map(|(id, summary)| {
            let has_error = snapshot
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
    // Project for output-boundary consistency. Finding counts are user-facing
    // (`KNOWN_USER`) so they survive `user-only`; routing every handler through
    // the guard keeps management uniform and fail-closed if an operator-shaped
    // field is ever added to the user summary.
    let audience = state.collector.config().audience;
    let snapshot = state.collector.snapshot().project_for_audience(audience);
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
    // Project: churn data points (`chaffra.findings.{new,resolved,unchanged,
    // churn_rate}`) are `KNOWN_USER` and survive `user-only`; the projection
    // strips any operator-classified point that would otherwise be readable here.
    let audience = state.collector.config().audience;
    let snapshot = state.collector.snapshot().project_for_audience(audience);
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
    // Project: per-module `health_score` points (`chaffra.module.<id>.health_score`)
    // are `KNOWN_USER` (user-facing analysis output) and survive `user-only`.
    let audience = state.collector.config().audience;
    let snapshot = state.collector.snapshot().project_for_audience(audience);
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
    let operator = config.audience.operator_enabled();

    // Backend kinds AND the sampling configuration are operator-shaped config
    // metadata — they describe the operator-telemetry emission policy (where
    // operator metrics go, and how often they are flushed). `project_for_audience`
    // scrubs the snapshot payload, not config metadata, so these need their own
    // audience gate here. Disclose them only under an operator-enabled audience;
    // under the default `user-only` (or `off`) the backend list is empty and the
    // sampling fields are withheld (`null`). R10-F2 (backends) + R13 (sampling).
    // The `audience` field itself is the user-facing mode and is always reported.
    let backends = if operator {
        config
            .backends
            .iter()
            .map(|b| format!("{:?}", b.kind))
            .collect()
    } else {
        Vec::new()
    };
    let (sampling_rate, sampling_strategy) = if operator {
        (
            Some(config.sampling_rate),
            Some(format!("{:?}", config.sampling_strategy)),
        )
    } else {
        (None, None)
    };

    Json(ConfigResponse {
        audience: format!("{:?}", config.audience),
        sampling_rate,
        sampling_strategy,
        backends,
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
}
