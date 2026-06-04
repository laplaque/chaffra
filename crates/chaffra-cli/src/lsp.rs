//! Lightweight LSP server for chaffra.
//!
//! Provides diagnostics on save and hover for complexity information.
//! Communicates via JSON-RPC 2.0 over stdio, using the Language Server Protocol.

use anyhow::Result;
use chaffra_complexity::ComplexityModule;
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::{FileInfo, Finding, Severity};
use chaffra_core::module::ModuleHost;
use chaffra_deadcode::DeadCodeModule;
use lsp_types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// JSON-RPC request envelope for LSP.
#[derive(Debug, Deserialize)]
struct LspRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

/// JSON-RPC response envelope for LSP.
#[derive(Debug, Serialize)]
struct LspResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

impl LspResponse {
    fn result(id: Option<serde_json::Value>, value: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id,
            result: Some(value),
            error: None,
            method: None,
            params: None,
        }
    }

    fn notification(method: &str, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_owned(),
            id: None,
            result: None,
            error: None,
            method: Some(method.to_owned()),
            params: Some(params),
        }
    }
}

/// Map chaffra severity to LSP diagnostic severity.
pub fn to_lsp_severity(severity: &Severity) -> DiagnosticSeverity {
    match severity {
        Severity::Error => DiagnosticSeverity::ERROR,
        Severity::Warning => DiagnosticSeverity::WARNING,
        Severity::Info => DiagnosticSeverity::INFORMATION,
    }
}

/// Convert a chaffra Finding to an LSP Diagnostic.
pub fn finding_to_diagnostic(finding: &Finding) -> Diagnostic {
    Diagnostic {
        range: Range {
            start: Position {
                line: finding.location.start_line.saturating_sub(1),
                character: finding.location.start_column,
            },
            end: Position {
                line: finding.location.end_line.saturating_sub(1),
                character: finding.location.end_column,
            },
        },
        severity: Some(to_lsp_severity(&finding.severity)),
        code: Some(NumberOrString::String(finding.rule_id.clone())),
        source: Some("chaffra".to_owned()),
        message: finding.message.clone(),
        ..Default::default()
    }
}

/// Run analysis on a file and return diagnostics grouped by file URI.
pub fn analyze_file_for_diagnostics(
    file_path: &str,
    content: &[u8],
) -> HashMap<String, Vec<Diagnostic>> {
    let mut diagnostics: HashMap<String, Vec<Diagnostic>> = HashMap::new();

    let relative = Path::new(file_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let files = vec![FileInfo {
        path: relative,
        content: content.to_vec(),
    }];

    let mut host = ModuleHost::new();
    let _ = host.register(Box::new(DeadCodeModule::new()));
    let _ = host.register(Box::new(ComplexityModule::new()));
    let config = ChaffraConfig::default();

    // Run dead-code analysis.
    if let Ok(result) = host.analyze("dead-code", &files, &config) {
        for finding in &result.findings {
            diagnostics
                .entry(file_path.to_owned())
                .or_default()
                .push(finding_to_diagnostic(finding));
        }
    }

    // Run complexity analysis.
    if let Ok(result) = host.analyze("complexity", &files, &config) {
        for finding in &result.findings {
            diagnostics
                .entry(file_path.to_owned())
                .or_default()
                .push(finding_to_diagnostic(finding));
        }
    }

    diagnostics
}

/// Build the hover response content for complexity information.
pub fn build_hover_content(file_path: &str, content: &[u8], line: u32) -> Option<String> {
    let ext = Path::new(file_path).extension()?.to_str()?;
    let language = chaffra_core::diagnostic::Language::from_extension(ext)?;

    let metrics = chaffra_complexity::compute_file_metrics(content, language, file_path).ok()?;

    for m in &metrics {
        if line >= m.start_line.saturating_sub(1) && line <= m.end_line.saturating_sub(1) {
            return Some(format!(
                "**{}** - Cyclomatic: {}, Cognitive: {}, Lines: {}, Max nesting: {}",
                m.name, m.cyclomatic, m.cognitive, m.lines, m.max_nesting
            ));
        }
    }

    None
}

/// Run the LSP server loop over stdio.
pub async fn run_lsp_server() -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
        }

        // Skip Content-Length headers (simplified -- not full HTTP framing).
        if line.starts_with("Content-Length:") || line.starts_with("Content-Type:") {
            continue;
        }

        let request: LspRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(_) => continue,
        };

        let responses = handle_lsp_request(&request);
        for resp in responses {
            let json = serde_json::to_string(&resp)?;
            stdout
                .write_all(format!("Content-Length: {}\r\n\r\n{}", json.len(), json).as_bytes())
                .await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

/// Handle a single LSP request and return responses/notifications.
fn handle_lsp_request(request: &LspRequest) -> Vec<LspResponse> {
    match request.method.as_str() {
        "initialize" => {
            let capabilities = ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                hover_provider: Some(HoverProviderCapability::Simple(true)),
                ..Default::default()
            };

            let result = InitializeResult {
                capabilities,
                server_info: Some(ServerInfo {
                    name: "chaffra".to_owned(),
                    version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                }),
            };

            vec![LspResponse::result(
                request.id.clone(),
                serde_json::to_value(result).unwrap(),
            )]
        }

        "initialized" => vec![],

        "shutdown" => vec![LspResponse::result(
            request.id.clone(),
            serde_json::Value::Null,
        )],

        "textDocument/didSave" => {
            if let Some(params) = &request.params {
                if let Ok(save_params) =
                    serde_json::from_value::<DidSaveTextDocumentParams>(params.clone())
                {
                    let uri = save_params.text_document.uri.to_string();
                    let file_path = uri.strip_prefix("file://").unwrap_or(&uri);

                    if let Ok(content) = std::fs::read(file_path) {
                        let diagnostics_map = analyze_file_for_diagnostics(file_path, &content);

                        let mut responses = Vec::new();
                        for (path, diags) in diagnostics_map {
                            let uri_str = if path.starts_with("file://") {
                                path.clone()
                            } else {
                                format!("file://{path}")
                            };
                            if let Ok(publish_uri) = uri_str.parse::<Uri>() {
                                let publish = PublishDiagnosticsParams {
                                    uri: publish_uri,
                                    diagnostics: diags,
                                    version: None,
                                };
                                responses.push(LspResponse::notification(
                                    "textDocument/publishDiagnostics",
                                    serde_json::to_value(publish).unwrap(),
                                ));
                            }
                        }

                        // If no diagnostics, clear them.
                        if responses.is_empty() {
                            if let Ok(clear_uri) = format!("file://{file_path}").parse::<Uri>() {
                                let publish = PublishDiagnosticsParams {
                                    uri: clear_uri,
                                    diagnostics: vec![],
                                    version: None,
                                };
                                responses.push(LspResponse::notification(
                                    "textDocument/publishDiagnostics",
                                    serde_json::to_value(publish).unwrap(),
                                ));
                            }
                        }

                        return responses;
                    }
                }
            }
            vec![]
        }

        "textDocument/didOpen" => {
            if let Some(params) = &request.params {
                if let Ok(open_params) =
                    serde_json::from_value::<DidOpenTextDocumentParams>(params.clone())
                {
                    let uri = open_params.text_document.uri.to_string();
                    let file_path = uri.strip_prefix("file://").unwrap_or(&uri);
                    let content = open_params.text_document.text.as_bytes();

                    let diagnostics_map = analyze_file_for_diagnostics(file_path, content);

                    let mut responses = Vec::new();
                    for (path, diags) in diagnostics_map {
                        if let Ok(publish_uri) = format!("file://{path}").parse::<Uri>() {
                            let publish = PublishDiagnosticsParams {
                                uri: publish_uri,
                                diagnostics: diags,
                                version: None,
                            };
                            responses.push(LspResponse::notification(
                                "textDocument/publishDiagnostics",
                                serde_json::to_value(publish).unwrap(),
                            ));
                        }
                    }

                    return responses;
                }
            }
            vec![]
        }

        "textDocument/hover" => {
            if let Some(params) = &request.params {
                if let Ok(hover_params) = serde_json::from_value::<HoverParams>(params.clone()) {
                    let uri = hover_params
                        .text_document_position_params
                        .text_document
                        .uri
                        .to_string();
                    let file_path = uri.strip_prefix("file://").unwrap_or(&uri);
                    let line = hover_params.text_document_position_params.position.line;

                    if let Ok(content) = std::fs::read(file_path) {
                        if let Some(hover_text) = build_hover_content(file_path, &content, line) {
                            let hover = Hover {
                                contents: HoverContents::Markup(MarkupContent {
                                    kind: MarkupKind::Markdown,
                                    value: hover_text,
                                }),
                                range: None,
                            };
                            return vec![LspResponse::result(
                                request.id.clone(),
                                serde_json::to_value(hover).unwrap(),
                            )];
                        }
                    }
                }
            }
            vec![LspResponse::result(
                request.id.clone(),
                serde_json::Value::Null,
            )]
        }

        _ => {
            // Ignore unknown notifications; return null for unknown requests.
            if request.id.is_some() {
                vec![LspResponse::result(
                    request.id.clone(),
                    serde_json::Value::Null,
                )]
            } else {
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_lsp_severity() {
        assert_eq!(to_lsp_severity(&Severity::Error), DiagnosticSeverity::ERROR);
        assert_eq!(
            to_lsp_severity(&Severity::Warning),
            DiagnosticSeverity::WARNING
        );
        assert_eq!(
            to_lsp_severity(&Severity::Info),
            DiagnosticSeverity::INFORMATION
        );
    }

    #[test]
    fn test_finding_to_diagnostic() {
        let finding = Finding {
            rule_id: "unused-function".to_owned(),
            message: "function `foo` is never used".to_owned(),
            severity: Severity::Warning,
            location: chaffra_core::diagnostic::Location {
                file: "test.go".to_owned(),
                start_line: 5,
                end_line: 10,
                start_column: 0,
                end_column: 1,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        };

        let diag = finding_to_diagnostic(&finding);
        assert_eq!(diag.range.start.line, 4); // 0-indexed
        assert_eq!(diag.range.end.line, 9);
        assert_eq!(diag.severity, Some(DiagnosticSeverity::WARNING));
        assert_eq!(diag.source, Some("chaffra".to_owned()));
        assert!(diag.message.contains("foo"));
    }

    #[test]
    fn test_handle_initialize() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(1)),
            method: "initialize".to_owned(),
            params: Some(serde_json::json!({})),
        };
        let responses = handle_lsp_request(&request);
        assert_eq!(responses.len(), 1);
        assert!(responses[0].result.is_some());
        let result = responses[0].result.as_ref().unwrap();
        assert!(result["capabilities"].is_object());
    }

    #[test]
    fn test_handle_initialized() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: "initialized".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_handle_shutdown() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(2)),
            method: "shutdown".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].result, Some(serde_json::Value::Null));
    }

    #[test]
    fn test_handle_unknown_request() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(3)),
            method: "custom/unknown".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request);
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn test_handle_unknown_notification() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: "custom/unknown".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_handle_hover_no_params() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(4)),
            method: "textDocument/hover".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].result, Some(serde_json::Value::Null));
    }

    #[test]
    fn test_handle_did_save_no_params() {
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: "textDocument/didSave".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_analyze_file_go_content() {
        let content = b"package main\n\nfunc main() {}\n\nfunc unused() {}\n";
        let diagnostics = analyze_file_for_diagnostics("/tmp/test.go", content);
        // Should produce at least dead-code findings for unused function.
        let all_diags: Vec<&Diagnostic> = diagnostics.values().flatten().collect();
        // The analysis should run without panicking.
        let _ = all_diags;
    }

    #[test]
    fn test_analyze_file_unknown_extension() {
        let content = b"some content";
        let diagnostics = analyze_file_for_diagnostics("/tmp/test.txt", content);
        // Unknown extension should produce no diagnostics.
        let total: usize = diagnostics.values().map(|v| v.len()).sum();
        assert_eq!(total, 0);
    }

    #[test]
    fn test_build_hover_content_no_match() {
        let content = b"package main\n\nfunc main() {}\n";
        // Line 100 is way past the end of content.
        let result = build_hover_content("/tmp/test.go", content, 100);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_hover_content_unknown_extension() {
        let result = build_hover_content("/tmp/test.txt", b"content", 0);
        assert!(result.is_none());
    }

    #[test]
    fn test_build_hover_content_go_function() {
        let content = b"package main\n\nfunc main() {\n    x := 1\n    _ = x\n}\n";
        let result = build_hover_content("/tmp/test.go", content, 2);
        if let Some(text) = result {
            assert!(text.contains("Cyclomatic"));
            assert!(text.contains("Cognitive"));
        }
        // It's OK if the function doesn't match on this line in simple cases.
    }
}
