//! MCP server: JSON-RPC 2.0 message loop over stdio.

use crate::protocol::{
    INTERNAL_ERROR, JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND, PARSE_ERROR,
};
use crate::tools;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// MCP server that reads JSON-RPC requests from stdin and writes responses to stdout.
pub struct McpServer {
    initialized: bool,
    live_state: chaffra_telemetry::LiveTelemetryState,
}

impl McpServer {
    /// Create a new MCP server.
    pub fn new(live_state: chaffra_telemetry::LiveTelemetryState) -> Self {
        Self {
            initialized: false,
            live_state,
        }
    }

    /// Run the server loop, reading from stdin and writing to stdout.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim().to_owned();
            if line.is_empty() {
                continue;
            }

            let response = self.handle_message(&line);

            if let Some(resp) = response {
                let json = serde_json::to_string(&resp)?;
                stdout.write_all(json.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }

        Ok(())
    }

    /// Handle a single JSON-RPC message and return an optional response.
    ///
    /// Notifications (no `id`) do not produce responses per JSON-RPC 2.0 spec.
    pub fn handle_message(&mut self, line: &str) -> Option<JsonRpcResponse> {
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(e) => {
                return Some(JsonRpcResponse::error(
                    None,
                    PARSE_ERROR,
                    format!("Parse error: {e}"),
                ));
            }
        };

        // Notifications have no id and expect no response.
        let is_notification = request.id.is_none();

        let response = match request.method.as_str() {
            "initialize" => Some(self.handle_initialize(&request)),
            "notifications/initialized" => {
                // No response needed for notifications.
                None
            }
            "tools/list" => Some(self.handle_tools_list(&request)),
            "tools/call" => Some(self.handle_tools_call(&request)),
            "shutdown" => Some(self.handle_shutdown(&request)),
            _ => {
                if is_notification {
                    None
                } else {
                    Some(JsonRpcResponse::error(
                        request.id.clone(),
                        METHOD_NOT_FOUND,
                        format!("Method not found: {}", request.method),
                    ))
                }
            }
        };

        // Suppress response for notifications even if handler produced one.
        if is_notification { None } else { response }
    }

    fn handle_initialize(&mut self, request: &JsonRpcRequest) -> JsonRpcResponse {
        self.initialized = true;
        JsonRpcResponse::success(
            request.id.clone(),
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "chaffra",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        )
    }

    fn handle_tools_list(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let tool_defs = tools::tool_definitions();
        JsonRpcResponse::success(
            request.id.clone(),
            serde_json::json!({ "tools": tool_defs }),
        )
    }

    fn handle_tools_call(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        let params = request
            .params
            .as_ref()
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(name) => name.to_owned(),
            None => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    INTERNAL_ERROR,
                    "Missing tool name in params".to_owned(),
                );
            }
        };

        let tool_args = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let result = tools::dispatch_tool(&tool_name, &tool_args, &self.live_state);
        JsonRpcResponse::success(request.id.clone(), serde_json::to_value(result).unwrap())
    }

    fn handle_shutdown(&self, request: &JsonRpcRequest) -> JsonRpcResponse {
        JsonRpcResponse::success(request.id.clone(), serde_json::json!(null))
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new(chaffra_telemetry::LiveTelemetryState::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
        let resp = server.handle_message(msg).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(
            result["serverInfo"]["name"]
                .as_str()
                .unwrap()
                .contains("chaffra")
        );
    }

    #[test]
    fn test_initialized_notification_no_response() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let resp = server.handle_message(msg);
        assert!(resp.is_none());
    }

    #[test]
    fn test_tools_list() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let resp = server.handle_message(msg).unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 4);
    }

    #[test]
    fn test_tools_call_explain() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"chaffra/explain","arguments":{"rule_id":"dead-code:unused-function"}}}"#;
        let resp = server.handle_message(msg).unwrap();
        let result = resp.result.unwrap();
        let content = result["content"].as_array().unwrap();
        assert!(!content.is_empty());
        assert!(content[0]["text"].as_str().unwrap().contains("unused"));
    }

    #[test]
    fn test_tools_call_missing_name() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}}"#;
        let resp = server.handle_message(msg).unwrap();
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_unknown_method() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":5,"method":"unknown/method"}"#;
        let resp = server.handle_message(msg).unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn test_unknown_notification_no_response() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","method":"unknown/notification"}"#;
        let resp = server.handle_message(msg);
        assert!(resp.is_none());
    }

    #[test]
    fn test_parse_error() {
        let mut server = McpServer::default();
        let resp = server.handle_message("not json").unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, PARSE_ERROR);
    }

    #[test]
    fn test_shutdown() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":6,"method":"shutdown"}"#;
        let resp = server.handle_message(msg).unwrap();
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap(), serde_json::json!(null));
    }

    #[test]
    fn test_tools_call_health_empty_dir() {
        let dir = std::env::temp_dir().join("chaffra_mcp_server_health");
        let _ = std::fs::create_dir_all(&dir);
        let mut server = McpServer::default();
        let msg = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"chaffra/health","arguments":{{"path":"{}"}}}}}}"#,
            dir.display()
        );
        let resp = server.handle_message(&msg).unwrap();
        assert!(resp.error.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_tools_call_unknown_tool() {
        let mut server = McpServer::default();
        let msg = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"unknown/tool","arguments":{}}}"#;
        let resp = server.handle_message(msg).unwrap();
        let result = resp.result.unwrap();
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_server_default() {
        let server = McpServer::default();
        assert!(!server.initialized);
    }
}
