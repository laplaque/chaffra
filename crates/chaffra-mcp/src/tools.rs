//! MCP tool implementations that dispatch to chaffra modules.

use crate::protocol::{ToolCallResult, ToolDefinition};
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::grpc::GrpcModuleHost;
use chaffra_deadcode::DeadCodeModule;
use std::path::Path;

/// Build a module host with all available built-in modules via gRPC.
pub fn build_module_host() -> GrpcModuleHost {
    let mut host = GrpcModuleHost::new();
    let _ = host.register(Box::new(DeadCodeModule::new()));
    let _ = host.register(Box::new(ComplexityModule::new()));
    host
}

fn merge_project_telemetry_config(
    server_config: &chaffra_telemetry::TelemetryConfig,
    project_config: &ChaffraConfig,
) -> chaffra_telemetry::TelemetryConfig {
    let module_cfg = project_config.module_config("telemetry");
    if module_cfg.is_empty() {
        return server_config.clone();
    }
    let project_tel = match chaffra_telemetry::TelemetryConfig::from_module_config(&module_cfg) {
        Ok(cfg) => cfg,
        Err(_) => return server_config.clone(),
    };

    let mut merged = server_config.clone();
    merged.sampling_rate = project_tel.sampling_rate;
    merged.sampling_strategy = project_tel.sampling_strategy;

    if matches!(
        project_tel.audience,
        chaffra_telemetry::TelemetryAudience::Off
    ) {
        merged.audience = chaffra_telemetry::TelemetryAudience::Off;
    }

    merged
}

fn record_analysis_and_push(
    host: &GrpcModuleHost,
    module_id: &str,
    files: &[FileInfo],
    config: &ChaffraConfig,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
) -> Result<chaffra_core::diagnostic::AnalysisResult, String> {
    if matches!(
        tel_config.audience,
        chaffra_telemetry::TelemetryAudience::Off
    ) {
        return host
            .analyze(module_id, files, config)
            .map_err(|e| e.to_string());
    }

    let collector = chaffra_telemetry::TelemetryCollector::new(tel_config.clone());
    collector.register_core_metrics();
    collector.set_files_total(files.len() as u64);
    let start = std::time::Instant::now();

    match host.analyze(module_id, files, config) {
        Ok(result) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            collector.record_module_call(module_id, duration_ms, false);
            let mut sev_counts = std::collections::HashMap::new();
            for finding in &result.findings {
                let sev = match finding.severity {
                    chaffra_core::diagnostic::Severity::Error => "error",
                    chaffra_core::diagnostic::Severity::Warning => "warning",
                    chaffra_core::diagnostic::Severity::Info => "info",
                };
                *sev_counts.entry(sev.to_owned()).or_insert(0u64) += 1;
            }
            collector.record_module_findings(module_id, result.findings.len() as u64, &sev_counts);
            let fingerprints: std::collections::HashSet<_> = result
                .findings
                .iter()
                .map(|f| {
                    chaffra_telemetry::churn::FindingFingerprint::new(
                        &f.rule_id,
                        &f.location.file,
                        f.location.start_line,
                    )
                })
                .collect();
            collector.set_finding_fingerprints(fingerprints.clone());

            let state_path = std::path::Path::new(chaffra_telemetry::churn::STATE_FILE);
            let previous_state = chaffra_telemetry::churn::load_state(state_path);
            let current_hash = chaffra_telemetry::churn::hash_fingerprints(&fingerprints);

            if let Some(ref prev) = previous_state {
                let churn = chaffra_telemetry::churn::compute_churn(&fingerprints, prev);
                collector.record_finding_churn(&churn);
            }

            let snapshot = collector.snapshot();
            live_state.push_snapshot(snapshot);

            let new_state = chaffra_telemetry::churn::ChurnState {
                fingerprints,
                findings_hash: current_hash,
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };
            let _ = chaffra_telemetry::churn::save_state(&new_state, state_path);

            Ok(result)
        }
        Err(e) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            collector.record_module_call(module_id, duration_ms, true);
            let snapshot = collector.snapshot();
            live_state.push_snapshot(snapshot);
            Err(e.to_string())
        }
    }
}

/// Return the list of available MCP tool definitions.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "chaffra/telemetry".to_owned(),
            description: "Query telemetry configuration: default backend setup, available backends, and preview metrics snapshot.".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Action to perform: 'status', 'snapshot', or 'backends'",
                        "enum": ["status", "snapshot", "backends"]
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "chaffra/health".to_owned(),
            description: "Compute a composite health score for the codebase. Returns score (0-100), grade (A-F), and per-file breakdown.".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the repository root (defaults to current directory)"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "chaffra/dead-code".to_owned(),
            description: "Detect dead code: unused functions, types, imports, and files.".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the repository root (defaults to current directory)"
                    }
                },
                "required": []
            }),
        },
        ToolDefinition {
            name: "chaffra/explain".to_owned(),
            description: "Explain a specific diagnostic rule in plain language. Rule IDs are formatted as 'module:rule' (e.g. 'dead-code:unused-function').".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Rule ID to explain (e.g. 'dead-code:unused-function')"
                    }
                },
                "required": ["rule_id"]
            }),
        },
    ]
}

/// Discover and read source files from a root directory.
fn discover_and_read_files(root: &Path, config: &ChaffraConfig) -> Vec<FileInfo> {
    let discovered = chaffra_parse::discovery::discover_files(root, &config.project.ignore);
    discovered
        .iter()
        .filter_map(|df| {
            let content = std::fs::read(&df.path).ok()?;
            Some(FileInfo {
                path: df.relative_path.clone(),
                content,
            })
        })
        .collect()
}

/// Execute the chaffra/health tool.
pub fn execute_health(
    params: &serde_json::Value,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
) -> ToolCallResult {
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    let config = ChaffraConfig::load_from_dir(&root).unwrap_or_default();
    let effective_tel = merge_project_telemetry_config(tel_config, &config);
    let files = discover_and_read_files(&root, &config);

    if files.is_empty() {
        return ToolCallResult::text("No source files found.".to_owned());
    }

    let host = build_module_host();
    let _ = record_analysis_and_push(
        &host,
        "complexity",
        &files,
        &config,
        live_state,
        &effective_tel,
    );

    match chaffra_complexity::analyze_project_health(
        &files,
        config.health.max_cyclomatic,
        config.health.max_cognitive,
    ) {
        Ok(health) => match serde_json::to_string_pretty(&health) {
            Ok(json) => ToolCallResult::text(json),
            Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
        },
        Err(e) => ToolCallResult::error(format!("Analysis error: {e}")),
    }
}

/// Execute the chaffra/dead-code tool.
pub fn execute_dead_code(
    params: &serde_json::Value,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
) -> ToolCallResult {
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    let config = ChaffraConfig::load_from_dir(&root).unwrap_or_default();
    let effective_tel = merge_project_telemetry_config(tel_config, &config);
    let files = discover_and_read_files(&root, &config);

    if files.is_empty() {
        return ToolCallResult::text("No source files found.".to_owned());
    }

    let host = build_module_host();
    match record_analysis_and_push(
        &host,
        "dead-code",
        &files,
        &config,
        live_state,
        &effective_tel,
    ) {
        Ok(result) => match serde_json::to_string_pretty(&result) {
            Ok(json) => ToolCallResult::text(json),
            Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
        },
        Err(e) => ToolCallResult::error(format!("Analysis error: {e}")),
    }
}

/// Execute the chaffra/explain tool.
pub fn execute_explain(params: &serde_json::Value) -> ToolCallResult {
    let rule_id = match params.get("rule_id").and_then(|v| v.as_str()) {
        Some(id) => id,
        None => return ToolCallResult::error("Missing required parameter: rule_id".to_owned()),
    };

    let host = build_module_host();
    match host.explain(rule_id) {
        Ok(explanation) => match serde_json::to_string_pretty(&explanation) {
            Ok(json) => ToolCallResult::text(json),
            Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
        },
        Err(e) => ToolCallResult::error(format!("Rule not found: {e}")),
    }
}

/// Execute the chaffra/telemetry tool.
///
/// `snapshot` reads from the shared live state; `status` and `backends` use
/// the effective telemetry config.
pub fn execute_telemetry(
    params: &serde_json::Value,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
) -> ToolCallResult {
    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("status");

    match action {
        "status" => {
            let (_, statuses) = chaffra_telemetry::backends::create_backends(&tel_config.backends);
            match serde_json::to_string_pretty(&statuses) {
                Ok(json) => ToolCallResult::text(json),
                Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
            }
        }
        "snapshot" => {
            let snapshot = match live_state.current() {
                Some(s) => {
                    if tel_config.audience.operator_enabled() {
                        s
                    } else {
                        s.user_scoped()
                    }
                }
                None => {
                    return ToolCallResult::text(
                        "No telemetry snapshots available yet.".to_owned(),
                    );
                }
            };
            match serde_json::to_string_pretty(&snapshot) {
                Ok(json) => ToolCallResult::text(json),
                Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
            }
        }
        "backends" => {
            let backends_info: Vec<serde_json::Value> = tel_config
                .backends
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "kind": format!("{:?}", b.kind),
                        "endpoint": b.endpoint,
                        "path": b.path,
                    })
                })
                .collect();
            match serde_json::to_string_pretty(&backends_info) {
                Ok(json) => ToolCallResult::text(json),
                Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
            }
        }
        _ => ToolCallResult::error(format!("Unknown telemetry action: {action}")),
    }
}

/// Dispatch a tool call by name.
pub fn dispatch_tool(
    name: &str,
    params: &serde_json::Value,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
) -> ToolCallResult {
    match name {
        "chaffra/health" => execute_health(params, live_state, tel_config),
        "chaffra/dead-code" => execute_dead_code(params, live_state, tel_config),
        "chaffra/explain" => execute_explain(params),
        "chaffra/telemetry" => execute_telemetry(params, live_state, tel_config),
        _ => ToolCallResult::error(format!("Unknown tool: {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definitions_count() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn test_tool_definitions_names() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"chaffra/health"));
        assert!(names.contains(&"chaffra/dead-code"));
        assert!(names.contains(&"chaffra/explain"));
        assert!(names.contains(&"chaffra/telemetry"));
    }

    #[test]
    fn test_tool_definitions_have_schemas() {
        for tool in tool_definitions() {
            assert!(
                tool.input_schema.is_object(),
                "tool {} missing schema",
                tool.name
            );
        }
    }

    fn tc() -> chaffra_telemetry::TelemetryConfig {
        chaffra_telemetry::TelemetryConfig::default()
    }

    #[test]
    fn test_dispatch_unknown_tool() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = dispatch_tool("unknown/tool", &serde_json::json!({}), &ls, &tc());
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("Unknown tool"));
    }

    #[test]
    fn test_explain_missing_rule_id() {
        let result = execute_explain(&serde_json::json!({}));
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("Missing required"));
    }

    #[test]
    fn test_explain_valid_rule() {
        let result = execute_explain(&serde_json::json!({"rule_id": "dead-code:unused-function"}));
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("unused"));
    }

    #[test]
    fn test_explain_unknown_rule() {
        let result = execute_explain(&serde_json::json!({"rule_id": "dead-code:nonexistent"}));
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_health_invalid_path() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = execute_health(
            &serde_json::json!({"path": "/nonexistent/path/xyz"}),
            &ls,
            &tc(),
        );
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("Invalid path"));
    }

    #[test]
    fn test_dead_code_invalid_path() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = execute_dead_code(
            &serde_json::json!({"path": "/nonexistent/path/xyz"}),
            &ls,
            &tc(),
        );
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("Invalid path"));
    }

    #[test]
    fn test_health_empty_dir() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let dir = std::env::temp_dir().join("chaffra_mcp_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let result = execute_health(
            &serde_json::json!({"path": dir.to_str().unwrap()}),
            &ls,
            &tc(),
        );
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("No source files"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dead_code_empty_dir() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let dir = std::env::temp_dir().join("chaffra_mcp_test_dc_empty");
        let _ = std::fs::create_dir_all(&dir);
        let result = execute_dead_code(
            &serde_json::json!({"path": dir.to_str().unwrap()}),
            &ls,
            &tc(),
        );
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("No source files"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dispatch_health() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let dir = std::env::temp_dir().join("chaffra_mcp_dispatch_health");
        let _ = std::fs::create_dir_all(&dir);
        let result = dispatch_tool(
            "chaffra/health",
            &serde_json::json!({"path": dir.to_str().unwrap()}),
            &ls,
            &tc(),
        );
        assert!(result.is_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dispatch_dead_code() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let dir = std::env::temp_dir().join("chaffra_mcp_dispatch_dc");
        let _ = std::fs::create_dir_all(&dir);
        let result = dispatch_tool(
            "chaffra/dead-code",
            &serde_json::json!({"path": dir.to_str().unwrap()}),
            &ls,
            &tc(),
        );
        assert!(result.is_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dispatch_explain() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = dispatch_tool(
            "chaffra/explain",
            &serde_json::json!({"rule_id": "dead-code:unused-function"}),
            &ls,
            &tc(),
        );
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_build_module_host_has_modules() {
        let host = build_module_host();
        let list = host.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_merge_project_telemetry_config_no_module_section() {
        let server = tc();
        let project = ChaffraConfig::default();
        let merged = merge_project_telemetry_config(&server, &project);
        assert_eq!(merged.audience, server.audience);
    }

    #[test]
    fn test_merge_project_telemetry_config_off_overrides() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert("audience".to_owned(), toml::Value::String("off".to_owned()));
        project.modules.insert("telemetry".to_owned(), tel_section);
        let merged = merge_project_telemetry_config(&server, &project);
        assert!(matches!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::Off
        ));
    }
}
