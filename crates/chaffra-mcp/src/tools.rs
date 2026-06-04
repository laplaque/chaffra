//! MCP tool implementations that dispatch to chaffra modules.

use crate::protocol::{ToolCallResult, ToolDefinition};
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::FileInfo;
use chaffra_core::module::ModuleHost;
use chaffra_deadcode::DeadCodeModule;
use std::path::Path;

/// Build a module host with all available built-in modules.
pub fn build_module_host() -> ModuleHost {
    let mut host = ModuleHost::new();
    let _ = host.register(Box::new(DeadCodeModule::new()));
    let _ = host.register(Box::new(ComplexityModule::new()));
    host
}

/// Return the list of available MCP tool definitions.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
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

    let config = ChaffraConfig::load_from_dir(&root).unwrap_or_default();
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

    let config = ChaffraConfig::load_from_dir(&root).unwrap_or_default();
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

/// Dispatch a tool call by name.
pub fn dispatch_tool(name: &str, params: &serde_json::Value) -> ToolCallResult {
    match name {
        "chaffra/health" => execute_health(params),
        "chaffra/dead-code" => execute_dead_code(params),
        "chaffra/explain" => execute_explain(params),
        _ => ToolCallResult::error(format!("Unknown tool: {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definitions_count() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn test_tool_definitions_names() {
        let tools = tool_definitions();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"chaffra/health"));
        assert!(names.contains(&"chaffra/dead-code"));
        assert!(names.contains(&"chaffra/explain"));
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
