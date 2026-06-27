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

/// Return the list of available MCP tool definitions.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "chaffra/telemetry".to_owned(),
            description: "Query telemetry configuration: default backend setup, available backends, and preview metrics snapshot. Resolves the project's '.chaffra.toml' [modules.telemetry] audience as the operator opt-in (default 'user-only'); operator-scoped fields are withheld unless the project file opts in. There is no request parameter to widen the audience.".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "Action to perform: 'status', 'snapshot', or 'backends'",
                        "enum": ["status", "snapshot", "backends"]
                    },
                    "path": {
                        "type": "string",
                        "description": "Path to the repository root whose .chaffra.toml resolves the telemetry audience (defaults to current directory)"
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
pub fn execute_health(params: &serde_json::Value) -> ToolCallResult {
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    // Fail closed on a malformed/unreadable `.chaffra.toml`, matching the CLI
    // strict loader (`chaffra-cli::load_config`). `unwrap_or_default()` here
    // would silently run against the default config — dropping a configured
    // telemetry audience or health thresholds without surfacing the error to
    // the MCP caller.
    let config = match ChaffraConfig::load_from_dir(&root) {
        Ok(c) => c,
        Err(e) => return ToolCallResult::error(format!("Invalid configuration: {e}")),
    };
    let files = discover_and_read_files(&root, &config);

    if files.is_empty() {
        return ToolCallResult::text("No source files found.".to_owned());
    }

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
pub fn execute_dead_code(params: &serde_json::Value) -> ToolCallResult {
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    // Fail closed on a malformed/unreadable `.chaffra.toml` (see execute_health).
    let config = match ChaffraConfig::load_from_dir(&root) {
        Ok(c) => c,
        Err(e) => return ToolCallResult::error(format!("Invalid configuration: {e}")),
    };
    let files = discover_and_read_files(&root, &config);

    if files.is_empty() {
        return ToolCallResult::text("No source files found.".to_owned());
    }

    let host = build_module_host();
    match host.analyze("dead-code", &files, &config) {
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
/// Returns the project's resolved telemetry view. The MCP entry point ALWAYS
/// runs at the project's resolved audience — a project with no
/// `[modules.telemetry]` section falls back to the Phase 15a.1 privacy default
/// (`user-only`). An MCP caller cannot widen the audience to see operator data
/// the project configuration would withhold (the audience is never taken from
/// request params; see R5-2 below).
///
/// Config resolution (R4-F1): the telemetry config is resolved from the
/// project's `.chaffra.toml` through the SAME strict loader the other MCP
/// tools and the CLI use — `ChaffraConfig::load_from_dir` (fail-closed on a
/// malformed/unreadable file) followed by
/// `TelemetryConfig::from_module_config` on the `[modules.telemetry]` section
/// (fail-closed on an invalid `audience`). There is no parallel
/// `TelemetryConfig::default()` path. This makes `[modules.telemetry]
/// audience = "on" | "operator-only"` an explicit operator opt-in for this
/// surface too, and surfaces malformed config as an error instead of
/// silently defaulting.
///
/// (R5-2: the audience is NEVER taken from the request params — the only
/// audience source is the project file, which an MCP client cannot tamper
/// with, so a caller cannot widen past the project's configured audience.
/// An earlier revision accepted an `audience` parameter here; that was a
/// widening attack vector and was removed. The operator branches are
/// exercised through the crate-internal [`execute_telemetry_with_config`]
/// helper, which is not reachable from external MCP callers.)
pub fn execute_telemetry(params: &serde_json::Value) -> ToolCallResult {
    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("status");
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    // Strict, shared config path (fail closed) — mirrors `execute_health` /
    // `execute_dead_code` and the CLI `load_config`.
    let project_config = match ChaffraConfig::load_from_dir(&root) {
        Ok(c) => c,
        Err(e) => return ToolCallResult::error(format!("Invalid configuration: {e}")),
    };

    // Derive the telemetry config from the project's `[modules.telemetry]`
    // section. Absent section -> `TelemetryConfig::default()` (audience =
    // `user-only`). Present section -> `from_module_config`, which defaults
    // the audience to `user-only` when the key is absent and fails closed on
    // an invalid `audience` value. No CLI flag participates on this surface,
    // so the file audience is the sole opt-in and cannot be widened by a
    // request param.
    let module_cfg = project_config.module_config("telemetry");
    let config = if module_cfg.is_empty() {
        chaffra_telemetry::TelemetryConfig::default()
    } else {
        match chaffra_telemetry::TelemetryConfig::from_module_config(&module_cfg) {
            Ok(c) => c,
            Err(e) => {
                return ToolCallResult::error(format!(
                    "Invalid [modules.telemetry] configuration: {e}"
                ));
            }
        }
    };

    execute_telemetry_with_config(action, &config)
}

/// Internal helper exposing the body of [`execute_telemetry`] with a
/// caller-supplied `TelemetryConfig`. EXISTS FOR TESTS ONLY — production
/// callers must go through [`execute_telemetry`], which pins the config to
/// the project default and cannot widen the audience. Direct callers
/// constructing their own `TelemetryConfig` are doing privileged work; the
/// MCP transport never reaches this entry point.
pub fn execute_telemetry_with_config(
    action: &str,
    config: &chaffra_telemetry::TelemetryConfig,
) -> ToolCallResult {
    let collector = chaffra_telemetry::TelemetryCollector::new(config.clone());
    collector.register_core_metrics();

    match action {
        "status" => {
            // Backend status is operator-shaped (backend kind, endpoint/path,
            // connectivity state). Match the `TelemetryModule::analyze`
            // backend-status finding rule (R4-1): expose only when the
            // resolved audience includes the operator scope (`On` /
            // `OperatorOnly`). The MCP entry point runs against a default
            // `TelemetryConfig`, so `user-only` (the new default) returns an
            // empty list rather than leaking the backend catalogue.
            if !config.audience.operator_enabled() {
                return ToolCallResult::text("[]".to_owned());
            }
            let (_, statuses) = chaffra_telemetry::backends::create_backends(&config.backends);
            match serde_json::to_string_pretty(&statuses) {
                Ok(json) => ToolCallResult::text(json),
                Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
            }
        }
        "snapshot" => {
            // R4-3: project the snapshot through the resolved audience BEFORE
            // serializing. This was previously serializing the raw snapshot,
            // which under default `user-only` would have exposed
            // `operator_summary`, every operator-scoped data point/span, and
            // the operator definition catalogue at this output boundary —
            // exactly the leak the CLI/module flush paths gate. The same rule
            // applies here: project before any user-facing emission.
            let snapshot = collector.snapshot().project_for_audience(config.audience);
            match serde_json::to_string_pretty(&snapshot) {
                Ok(json) => ToolCallResult::text(json),
                Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
            }
        }
        "backends" => {
            // Same gate as `status` (R4-1/R4-3 parallel path): the configured
            // backends list is operator-shaped (kind/endpoint/path discloses
            // where telemetry would be sent). Withhold under audiences that
            // don't include the operator scope, matching the projection rule
            // that drops `OperatorSummary` and operator-scoped data points.
            if !config.audience.operator_enabled() {
                return ToolCallResult::text("[]".to_owned());
            }
            let backends_info: Vec<serde_json::Value> = config
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
pub fn dispatch_tool(name: &str, params: &serde_json::Value) -> ToolCallResult {
    match name {
        "chaffra/health" => execute_health(params),
        "chaffra/dead-code" => execute_dead_code(params),
        "chaffra/explain" => execute_explain(params),
        "chaffra/telemetry" => execute_telemetry(params),
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

    #[test]
    fn test_dispatch_unknown_tool() {
        let result = dispatch_tool("unknown/tool", &serde_json::json!({}));
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
        let result = execute_health(&serde_json::json!({"path": "/nonexistent/path/xyz"}));
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("Invalid path"));
    }

    #[test]
    fn test_dead_code_invalid_path() {
        let result = execute_dead_code(&serde_json::json!({"path": "/nonexistent/path/xyz"}));
        assert_eq!(result.is_error, Some(true));
        assert!(result.content[0].text.contains("Invalid path"));
    }

    #[test]
    fn test_health_empty_dir() {
        let dir = std::env::temp_dir().join("chaffra_mcp_test_empty");
        let _ = std::fs::create_dir_all(&dir);
        let result = execute_health(&serde_json::json!({"path": dir.to_str().unwrap()}));
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("No source files"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dead_code_empty_dir() {
        let dir = std::env::temp_dir().join("chaffra_mcp_test_dc_empty");
        let _ = std::fs::create_dir_all(&dir);
        let result = execute_dead_code(&serde_json::json!({"path": dir.to_str().unwrap()}));
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("No source files"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dispatch_health() {
        let dir = std::env::temp_dir().join("chaffra_mcp_dispatch_health");
        let _ = std::fs::create_dir_all(&dir);
        let result = dispatch_tool(
            "chaffra/health",
            &serde_json::json!({"path": dir.to_str().unwrap()}),
        );
        assert!(result.is_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dispatch_dead_code() {
        let dir = std::env::temp_dir().join("chaffra_mcp_dispatch_dc");
        let _ = std::fs::create_dir_all(&dir);
        let result = dispatch_tool(
            "chaffra/dead-code",
            &serde_json::json!({"path": dir.to_str().unwrap()}),
        );
        assert!(result.is_error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dispatch_explain() {
        let result = dispatch_tool(
            "chaffra/explain",
            &serde_json::json!({"rule_id": "dead-code:unused-function"}),
        );
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_build_module_host_has_modules() {
        let host = build_module_host();
        let list = host.list();
        assert_eq!(list.len(), 2);
    }
}
