//! JSON-RPC 2.0 protocol types for MCP communication.

use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    /// Create a success response.
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: Option<serde_json::Value>, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

// Standard JSON-RPC error codes.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INTERNAL_ERROR: i64 = -32603;

/// MCP tool definition for the tools/list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// MCP tool call result content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultContent {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

/// MCP tool call result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    pub content: Vec<ToolResultContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "isError")]
    pub is_error: Option<bool>,
}

impl ToolCallResult {
    /// Create a successful text result.
    pub fn text(text: String) -> Self {
        Self {
            content: vec![ToolResultContent {
                content_type: "text".to_owned(),
                text,
            }],
            is_error: None,
        }
    }

    /// Create an error text result.
    pub fn error(message: String) -> Self {
        Self {
            content: vec![ToolResultContent {
                content_type: "text".to_owned(),
                text: message,
            }],
            is_error: Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "initialize");
        assert_eq!(req.jsonrpc, "2.0");
    }

    #[test]
    fn test_parse_request_no_params() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tools/list");
        assert!(req.params.is_none());
    }

    #[test]
    fn test_parse_request_notification() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert!(req.id.is_none());
    }

    #[test]
    fn test_success_response() {
        let resp = JsonRpcResponse::success(
            Some(serde_json::Value::Number(1.into())),
            serde_json::json!({"ok": true}),
        );
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"ok\""));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_error_response() {
        let resp = JsonRpcResponse::error(
            Some(serde_json::Value::Number(1.into())),
            METHOD_NOT_FOUND,
            "Method not found".to_owned(),
        );
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.as_ref().unwrap().code, METHOD_NOT_FOUND);
    }

    #[test]
    fn test_tool_result_text() {
        let result = ToolCallResult::text("hello".to_owned());
        assert_eq!(result.content.len(), 1);
        assert_eq!(result.content[0].content_type, "text");
        assert!(result.is_error.is_none());
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolCallResult::error("fail".to_owned());
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = ToolDefinition {
            name: "chaffra/health".to_owned(),
            description: "Get health score".to_owned(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                }
            }),
        };
        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("inputSchema"));
        assert!(json.contains("chaffra/health"));
    }
}
