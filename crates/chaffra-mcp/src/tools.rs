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
    explicit_cli_audience: bool,
) -> Result<chaffra_telemetry::TelemetryConfig, String> {
    let module_cfg = project_config.module_config("telemetry");
    if module_cfg.is_empty() {
        return Ok(server_config.clone());
    }
    server_config.merge_project_config(&module_cfg, explicit_cli_audience)
}

fn record_analysis_and_push(
    host: &GrpcModuleHost,
    module_id: &str,
    files: &[FileInfo],
    config: &ChaffraConfig,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
    project_root: &Path,
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
            collector.set_finding_fingerprints(fingerprints);

            chaffra_telemetry::finalize_and_flush_sampled(
                &collector,
                live_state,
                tel_config,
                project_root,
            );

            Ok(result)
        }
        Err(e) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            collector.record_module_call(module_id, duration_ms, true);
            chaffra_telemetry::flush_snapshot(&collector, live_state, tel_config);
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
    explicit_cli_audience: bool,
    config_path: Option<&str>,
) -> ToolCallResult {
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    let config = if let Some(cfg_path) = config_path {
        let p = Path::new(cfg_path);
        if p.exists() {
            match ChaffraConfig::load(p) {
                Ok(c) => c,
                Err(e) => {
                    return ToolCallResult::error(format!("Malformed config at {cfg_path}: {e}"));
                }
            }
        } else {
            return ToolCallResult::error(format!("Config file not found: {cfg_path}"));
        }
    } else {
        match ChaffraConfig::load_from_dir(&root) {
            Ok(c) => c,
            Err(e) => {
                if root.join(".chaffra.toml").exists() {
                    return ToolCallResult::error(format!("Malformed project config: {e}"));
                }
                ChaffraConfig::default()
            }
        }
    };
    let effective_tel =
        match merge_project_telemetry_config(tel_config, &config, explicit_cli_audience) {
            Ok(cfg) => cfg,
            Err(e) => return ToolCallResult::error(format!("Invalid telemetry config: {e}")),
        };
    let files = discover_and_read_files(&root, &config);

    if files.is_empty() {
        return ToolCallResult::text("No source files found.".to_owned());
    }

    // Run health analysis once; record telemetry from its result.
    let tel_active = !matches!(
        effective_tel.audience,
        chaffra_telemetry::TelemetryAudience::Off
    );

    let collector = if tel_active {
        let c = chaffra_telemetry::TelemetryCollector::new(effective_tel.clone());
        c.register_core_metrics();
        c.set_files_total(files.len() as u64);
        Some(c)
    } else {
        None
    };

    let start = std::time::Instant::now();
    let health = match chaffra_complexity::analyze_project_health(
        &files,
        config.health.max_cyclomatic,
        config.health.max_cognitive,
    ) {
        Ok(h) => h,
        Err(e) => {
            if let Some(ref collector) = collector {
                let duration_ms = start.elapsed().as_millis() as u64;
                collector.record_module_call("complexity", duration_ms, true);
                chaffra_telemetry::flush_snapshot(collector, live_state, &effective_tel);
            }
            return ToolCallResult::error(format!("Analysis error: {e}"));
        }
    };

    if let Some(ref collector) = collector {
        let duration_ms = start.elapsed().as_millis() as u64;
        collector.record_module_call("complexity", duration_ms, false);

        // Only count problem files (score < 80) as findings.
        let mut sev_counts = std::collections::HashMap::new();
        let mut fingerprints = std::collections::HashSet::new();
        for file_score in &health.files {
            if file_score.score < 60 {
                *sev_counts.entry("error".to_owned()).or_insert(0u64) += 1;
                fingerprints.insert(chaffra_telemetry::churn::FindingFingerprint::new(
                    "complexity:health",
                    &file_score.file,
                    0,
                ));
            } else if file_score.score < 80 {
                *sev_counts.entry("warning".to_owned()).or_insert(0u64) += 1;
                fingerprints.insert(chaffra_telemetry::churn::FindingFingerprint::new(
                    "complexity:health",
                    &file_score.file,
                    0,
                ));
            }
        }
        let finding_count: u64 = sev_counts.values().sum();
        collector.record_module_findings("complexity", finding_count, &sev_counts);
        collector.set_finding_fingerprints(fingerprints);

        chaffra_telemetry::finalize_and_flush_sampled(collector, live_state, &effective_tel, &root);
    }

    match serde_json::to_string_pretty(&health) {
        Ok(json) => ToolCallResult::text(json),
        Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
    }
}

/// Execute the chaffra/dead-code tool.
pub fn execute_dead_code(
    params: &serde_json::Value,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
    explicit_cli_audience: bool,
    config_path: Option<&str>,
) -> ToolCallResult {
    let path = params.get("path").and_then(|v| v.as_str()).unwrap_or(".");

    let root = match Path::new(path).canonicalize() {
        Ok(r) => r,
        Err(e) => return ToolCallResult::error(format!("Invalid path: {e}")),
    };

    let config = if let Some(cfg_path) = config_path {
        let p = Path::new(cfg_path);
        if p.exists() {
            match ChaffraConfig::load(p) {
                Ok(c) => c,
                Err(e) => {
                    return ToolCallResult::error(format!("Malformed config at {cfg_path}: {e}"));
                }
            }
        } else {
            return ToolCallResult::error(format!("Config file not found: {cfg_path}"));
        }
    } else {
        match ChaffraConfig::load_from_dir(&root) {
            Ok(c) => c,
            Err(e) => {
                if root.join(".chaffra.toml").exists() {
                    return ToolCallResult::error(format!("Malformed project config: {e}"));
                }
                ChaffraConfig::default()
            }
        }
    };
    let effective_tel =
        match merge_project_telemetry_config(tel_config, &config, explicit_cli_audience) {
            Ok(cfg) => cfg,
            Err(e) => return ToolCallResult::error(format!("Invalid telemetry config: {e}")),
        };
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
        &root,
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
/// the effective telemetry config (merged with project overrides when
/// `config_path` is provided).
pub fn execute_telemetry(
    params: &serde_json::Value,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
    explicit_cli_audience: bool,
    config_path: Option<&str>,
) -> ToolCallResult {
    let action = params
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("status");

    let effective_tel = if let Some(cfg_path) = config_path {
        let p = Path::new(cfg_path);
        if !p.exists() {
            return ToolCallResult::error(format!("Explicit config not found: {cfg_path}"));
        }
        match ChaffraConfig::load(p) {
            Ok(project_config) => {
                let module_cfg = project_config.module_config("telemetry");
                if module_cfg.is_empty() {
                    tel_config.clone()
                } else {
                    match tel_config.merge_project_config(&module_cfg, explicit_cli_audience) {
                        Ok(merged) => merged,
                        Err(e) => {
                            return ToolCallResult::error(format!("Invalid telemetry config: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                return ToolCallResult::error(format!("Malformed config: {e}"));
            }
        }
    } else {
        tel_config.clone()
    };

    match action {
        "status" => {
            if matches!(
                effective_tel.audience,
                chaffra_telemetry::TelemetryAudience::Off
            ) {
                return ToolCallResult::text("[]".to_owned());
            }
            let (_, statuses) =
                chaffra_telemetry::backends::create_backends(&effective_tel.backends);
            match serde_json::to_string_pretty(&statuses) {
                Ok(json) => ToolCallResult::text(json),
                Err(e) => ToolCallResult::error(format!("Serialization error: {e}")),
            }
        }
        "snapshot" => {
            let snapshot = match live_state.current() {
                Some(s) => s.project_for_audience(effective_tel.audience),
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
            if matches!(
                effective_tel.audience,
                chaffra_telemetry::TelemetryAudience::Off
            ) {
                return ToolCallResult::text("[]".to_owned());
            }
            let backends_info: Vec<serde_json::Value> = effective_tel
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
    explicit_cli_audience: bool,
    config_path: Option<&str>,
) -> ToolCallResult {
    match name {
        "chaffra/health" => execute_health(
            params,
            live_state,
            tel_config,
            explicit_cli_audience,
            config_path,
        ),
        "chaffra/dead-code" => execute_dead_code(
            params,
            live_state,
            tel_config,
            explicit_cli_audience,
            config_path,
        ),
        "chaffra/explain" => execute_explain(params),
        "chaffra/telemetry" => execute_telemetry(
            params,
            live_state,
            tel_config,
            explicit_cli_audience,
            config_path,
        ),
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
        let result = dispatch_tool(
            "unknown/tool",
            &serde_json::json!({}),
            &ls,
            &tc(),
            false,
            None,
        );
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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
            false,
            None,
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
        let merged = merge_project_telemetry_config(&server, &project, false).unwrap();
        assert_eq!(merged.audience, server.audience);
    }

    #[test]
    fn test_merge_project_telemetry_config_off_overrides() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert("audience".to_owned(), toml::Value::String("off".to_owned()));
        project.modules.insert("telemetry".to_owned(), tel_section);
        let merged = merge_project_telemetry_config(&server, &project, false).unwrap();
        assert!(matches!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::Off
        ));
    }

    #[test]
    fn test_merge_project_telemetry_config_invalid_audience_fails_closed() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert(
            "audience".to_owned(),
            toml::Value::String("bogus".to_owned()),
        );
        project.modules.insert("telemetry".to_owned(), tel_section);
        let result = merge_project_telemetry_config(&server, &project, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_project_telemetry_config_sampling() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert(
            "sampling-rate".to_owned(),
            toml::Value::String("0.5".to_owned()),
        );
        tel_section.insert(
            "sampling-strategy".to_owned(),
            toml::Value::String("on-change".to_owned()),
        );
        project.modules.insert("telemetry".to_owned(), tel_section);
        let merged = merge_project_telemetry_config(&server, &project, false).unwrap();
        assert!((merged.sampling_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_merge_project_telemetry_config_operator_opt_in() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert("audience".to_owned(), toml::Value::String("on".to_owned()));
        project.modules.insert("telemetry".to_owned(), tel_section);
        let merged = merge_project_telemetry_config(&server, &project, false).unwrap();
        assert_eq!(merged.audience, chaffra_telemetry::TelemetryAudience::On);
    }

    #[test]
    fn test_merge_project_telemetry_config_operator_only() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert(
            "audience".to_owned(),
            toml::Value::String("operator-only".to_owned()),
        );
        project.modules.insert("telemetry".to_owned(), tel_section);
        let merged = merge_project_telemetry_config(&server, &project, false).unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly
        );
    }

    #[test]
    fn test_merge_project_telemetry_config_invalid_backend_fails_closed() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert(
            "backend".to_owned(),
            toml::Value::String("bogus-sink".to_owned()),
        );
        project.modules.insert("telemetry".to_owned(), tel_section);
        let result = merge_project_telemetry_config(&server, &project, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_project_telemetry_config_invalid_sampling_rate_fails_closed() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert(
            "sampling-rate".to_owned(),
            toml::Value::String("not-a-number".to_owned()),
        );
        project.modules.insert("telemetry".to_owned(), tel_section);
        let result = merge_project_telemetry_config(&server, &project, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_project_telemetry_config_invalid_sampling_strategy_fails_closed() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert(
            "sampling-strategy".to_owned(),
            toml::Value::String("bogus-strategy".to_owned()),
        );
        project.modules.insert("telemetry".to_owned(), tel_section);
        let result = merge_project_telemetry_config(&server, &project, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_project_telemetry_config_explicit_cli_audience_wins() {
        let server = tc();
        let mut project = ChaffraConfig::default();
        let mut tel_section = std::collections::HashMap::new();
        tel_section.insert("audience".to_owned(), toml::Value::String("on".to_owned()));
        project.modules.insert("telemetry".to_owned(), tel_section);
        let merged = merge_project_telemetry_config(&server, &project, true).unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly,
            "explicit CLI audience must override project config"
        );
    }

    #[test]
    fn test_record_analysis_and_push_off_mode() {
        let host = build_module_host();
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let mut off_config = tc();
        off_config.audience = chaffra_telemetry::TelemetryAudience::Off;
        let config = ChaffraConfig::default();
        let result = record_analysis_and_push(
            &host,
            "dead-code",
            &[],
            &config,
            &ls,
            &off_config,
            Path::new("."),
        );
        assert!(result.is_ok());
        assert!(ls.current().is_none());
    }

    #[test]
    fn test_record_analysis_and_push_populates_live_state() {
        let tmp = tempfile::tempdir().unwrap();
        let host = build_module_host();
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let config = ChaffraConfig::default();
        let result =
            record_analysis_and_push(&host, "dead-code", &[], &config, &ls, &tc(), tmp.path());
        assert!(result.is_ok());
        assert!(ls.current().is_some());
    }

    #[test]
    fn test_dispatch_telemetry_status() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = dispatch_tool(
            "chaffra/telemetry",
            &serde_json::json!({"action": "status"}),
            &ls,
            &tc(),
            false,
            None,
        );
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_dispatch_telemetry_snapshot_empty() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = dispatch_tool(
            "chaffra/telemetry",
            &serde_json::json!({"action": "snapshot"}),
            &ls,
            &tc(),
            false,
            None,
        );
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("No telemetry"));
    }

    #[test]
    fn test_dispatch_telemetry_backends() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = dispatch_tool(
            "chaffra/telemetry",
            &serde_json::json!({"action": "backends"}),
            &ls,
            &tc(),
            false,
            None,
        );
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_dispatch_telemetry_unknown_action() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = dispatch_tool(
            "chaffra/telemetry",
            &serde_json::json!({"action": "invalid"}),
            &ls,
            &tc(),
            false,
            None,
        );
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_telemetry_missing_explicit_config_errors() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = execute_telemetry(
            &serde_json::json!({"action": "status"}),
            &ls,
            &tc(),
            false,
            Some("/nonexistent/chaffra.toml"),
        );
        assert_eq!(result.is_error, Some(true));
        assert!(
            result.content[0].text.contains("Explicit config not found"),
            "should error when explicit config_path doesn't exist, got: {}",
            result.content[0].text
        );
    }

    #[test]
    fn test_health_missing_explicit_config_errors() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let result = execute_health(
            &serde_json::json!({}),
            &ls,
            &tc(),
            false,
            Some("/nonexistent/chaffra.toml"),
        );
        assert_eq!(result.is_error, Some(true));
        assert!(
            result.content[0].text.contains("Config file not found"),
            "should error when explicit config_path doesn't exist, got: {}",
            result.content[0].text
        );
    }

    // ---- Test module that produces Error-severity findings ----

    use chaffra_core::diagnostic::*;
    use chaffra_core::module::{AnalysisModule, empty_metrics};

    struct ErrorSeverityModule;

    impl AnalysisModule for ErrorSeverityModule {
        fn describe(&self) -> ModuleInfo {
            ModuleInfo {
                id: "error-mod".to_owned(),
                name: "Error Module".to_owned(),
                version: "0.1.0".to_owned(),
                languages: vec!["go".to_owned()],
                capabilities: vec!["analyze".to_owned()],
                rules: vec![Rule {
                    id: "err-rule".to_owned(),
                    name: "Error Rule".to_owned(),
                    description: "A rule that emits Error findings".to_owned(),
                    default_severity: Severity::Error,
                    category: "test".to_owned(),
                }],
            }
        }

        fn analyze(
            &self,
            files: &[FileInfo],
            _config: &std::collections::HashMap<String, String>,
        ) -> chaffra_core::error::Result<AnalysisResult> {
            Ok(AnalysisResult {
                findings: vec![
                    Finding {
                        rule_id: "err-rule".to_owned(),
                        message: "critical error finding".to_owned(),
                        severity: Severity::Error,
                        location: Location {
                            file: "main.go".to_owned(),
                            start_line: 10,
                            end_line: 15,
                            start_column: 0,
                            end_column: 20,
                        },
                        confidence: 0.99,
                        actions: vec![],
                        metadata: std::collections::HashMap::new(),
                    },
                    Finding {
                        rule_id: "err-rule".to_owned(),
                        message: "warning finding".to_owned(),
                        severity: Severity::Warning,
                        location: Location {
                            file: "util.go".to_owned(),
                            start_line: 5,
                            end_line: 5,
                            start_column: 0,
                            end_column: 10,
                        },
                        confidence: 0.8,
                        actions: vec![],
                        metadata: std::collections::HashMap::new(),
                    },
                ],
                metrics: empty_metrics(files.len() as u64),
            })
        }

        fn explain(&self, _rule_id: &str) -> chaffra_core::error::Result<RuleExplanation> {
            Err(chaffra_core::error::ChaffraError::RuleNotFound(
                "not implemented".to_owned(),
            ))
        }

        fn fix(
            &self,
            _findings: &[Finding],
            _dry_run: bool,
        ) -> chaffra_core::error::Result<Vec<FixResult>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_record_analysis_error_severity_findings() {
        let mut host = GrpcModuleHost::new();
        let _ = host.register(Box::new(ErrorSeverityModule));
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let config = ChaffraConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let result =
            record_analysis_and_push(&host, "error-mod", &[], &config, &ls, &tc(), tmp.path());
        assert!(result.is_ok());
        let analysis = result.unwrap();
        // Verify we got findings with both Error and Warning severity.
        assert_eq!(analysis.findings.len(), 2);
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.severity == Severity::Error)
        );
        assert!(
            analysis
                .findings
                .iter()
                .any(|f| f.severity == Severity::Warning)
        );
        // Verify telemetry was populated.
        let snapshot = ls.current().expect("live state should have a snapshot");
        let sev = &snapshot.user_summary.findings_by_severity;
        assert_eq!(sev.get("error"), Some(&1));
        assert_eq!(sev.get("warning"), Some(&1));
    }

    #[test]
    fn test_record_analysis_and_push_err_path() {
        let host = build_module_host();
        let ls = chaffra_telemetry::LiveTelemetryState::new();
        let config = ChaffraConfig::default();
        // Pass an unknown module_id to trigger the Err branch.
        let tmp = tempfile::tempdir().unwrap();
        let result = record_analysis_and_push(
            &host,
            "nonexistent-module",
            &[],
            &config,
            &ls,
            &tc(),
            tmp.path(),
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("nonexistent-module"),
            "error should mention the missing module id, got: {err_msg}"
        );
        // The Err path calls flush_snapshot, which should populate live state.
        assert!(
            ls.current().is_some(),
            "flush_snapshot should populate live state even on error"
        );
    }

    #[test]
    fn test_telemetry_snapshot_operator_scoped() {
        let ls = chaffra_telemetry::LiveTelemetryState::new();

        // Build a snapshot with operator-level data (module_call_durations).
        let mut module_call_durations = std::collections::HashMap::new();
        module_call_durations.insert("dead-code".to_owned(), 42u64);
        let snapshot = chaffra_telemetry::collector::TelemetrySnapshot {
            timestamp_ms: 1000,
            definitions: std::collections::HashMap::new(),
            data_points: vec![chaffra_telemetry::MetricDataPoint {
                name: "chaffra.module.call_duration_ms".to_owned(),
                value: 42.0,
                labels: {
                    let mut m = std::collections::HashMap::new();
                    m.insert("module".to_owned(), "dead-code".to_owned());
                    m
                },
                timestamp_ms: 1000,
                user_scoped: false,
            }],
            spans: vec![],
            user_summary: chaffra_telemetry::collector::UserSummary {
                analysis_duration_ms: 100,
                files_total: 5,
                findings_by_severity: std::collections::HashMap::new(),
                findings_by_module: std::collections::HashMap::new(),
                module_summaries: std::collections::HashMap::new(),
            },
            operator_summary: chaffra_telemetry::collector::OperatorSummary {
                module_call_durations,
                module_error_counts: std::collections::HashMap::new(),
            },
        };
        ls.push_snapshot(snapshot);

        // With TelemetryAudience::On, project_for_audience returns the full snapshot.
        let mut on_config = tc();
        on_config.audience = chaffra_telemetry::TelemetryAudience::On;
        let result = execute_telemetry(
            &serde_json::json!({"action": "snapshot"}),
            &ls,
            &on_config,
            false,
            None,
        );
        assert!(result.is_error.is_none());
        let text = &result.content[0].text;
        // The full snapshot includes operator data: module_call_durations with "dead-code".
        assert!(
            text.contains("module_call_durations"),
            "operator-scoped snapshot should include module_call_durations"
        );
        assert!(
            text.contains("dead-code"),
            "operator-scoped snapshot should include module name"
        );

        // With default audience (UserOnly), project_for_audience strips
        // operator data, returning a user-scoped snapshot.
        let result_user = execute_telemetry(
            &serde_json::json!({"action": "snapshot"}),
            &ls,
            &tc(),
            false,
            None,
        );
        assert!(result_user.is_error.is_none());
        let user_text = &result_user.content[0].text;
        // The user-scoped snapshot zeroes out operator_summary.
        let parsed: serde_json::Value =
            serde_json::from_str(user_text).expect("should be valid JSON");
        let op_durations = &parsed["operator_summary"]["module_call_durations"];
        assert!(
            op_durations.as_object().is_none_or(|m| m.is_empty()),
            "user-scoped snapshot should have empty module_call_durations"
        );
    }
}
