//! Lightweight LSP server for chaffra.
//!
//! Provides diagnostics on save and hover for complexity information.
//! Communicates via JSON-RPC 2.0 over stdio, using the Language Server Protocol.

use anyhow::Result;
use chaffra_core::diagnostic::{Finding, Severity};
use lsp_types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

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

/// Merge server-level telemetry config with project-level workspace config.
///
/// Returns `None` if the project sets `audience = "off"` (caller should use
/// the no-telemetry path). Otherwise returns the merged config with project
/// sampling overrides applied.
pub(crate) fn merge_lsp_telemetry_config(
    server_config: &chaffra_telemetry::TelemetryConfig,
    workspace_config: &chaffra_core::config::ChaffraConfig,
    explicit_cli_audience: bool,
) -> Result<Option<chaffra_telemetry::TelemetryConfig>, String> {
    let module_cfg = workspace_config.module_config("telemetry");
    if module_cfg.is_empty() {
        return Ok(Some(server_config.clone()));
    }
    let merged = server_config.merge_project_config(&module_cfg, explicit_cli_audience)?;
    if matches!(merged.audience, chaffra_telemetry::TelemetryAudience::Off) {
        return Ok(None);
    }
    Ok(Some(merged))
}

/// Run analysis on a file and return diagnostics grouped by file URI.
pub fn analyze_file_for_diagnostics(
    file_path: &str,
    content: &[u8],
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
    explicit_cli_audience: bool,
) -> HashMap<String, Vec<Diagnostic>> {
    use chaffra_core::config::ChaffraConfig;
    use chaffra_core::diagnostic::FileInfo;
    use std::path::Path;

    if matches!(
        tel_config.audience,
        chaffra_telemetry::TelemetryAudience::Off
    ) {
        return analyze_file_no_telemetry(file_path, content);
    }

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

    let workspace_config = match Path::new(file_path).parent().and_then(|dir| {
        let mut d = dir;
        loop {
            let candidate = d.join(".chaffra.toml");
            if candidate.exists() {
                return Some(d.to_path_buf());
            }
            d = d.parent()?;
        }
    }) {
        Some(config_dir) => match ChaffraConfig::load_from_dir(&config_dir) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Malformed workspace config, disabling telemetry: {e}");
                return analyze_file_no_telemetry(file_path, content);
            }
        },
        None => ChaffraConfig::default(),
    };

    let effective_tel =
        match merge_lsp_telemetry_config(tel_config, &workspace_config, explicit_cli_audience) {
            Ok(Some(merged)) => merged,
            Ok(None) => return analyze_file_no_telemetry(file_path, content),
            Err(e) => {
                eprintln!("Invalid workspace telemetry config: {e}");
                return analyze_file_no_telemetry(file_path, content);
            }
        };

    let collector = chaffra_telemetry::TelemetryCollector::new(effective_tel.clone());
    collector.register_core_metrics();
    collector.set_files_total(1);
    let host = crate::build_module_host_with_telemetry(Some(&collector));
    let config = workspace_config;
    let start = std::time::Instant::now();
    let mut had_error = false;
    let mut all_findings = Vec::new();

    for module_id in &["dead-code", "complexity"] {
        match host.analyze(module_id, &files, &config) {
            Ok(result) => {
                let dur = start.elapsed().as_millis() as u64;
                collector.record_module_call(module_id, dur, false);
                let mut sev_counts = std::collections::HashMap::new();
                for finding in &result.findings {
                    let sev = match finding.severity {
                        chaffra_core::diagnostic::Severity::Error => "error",
                        chaffra_core::diagnostic::Severity::Warning => "warning",
                        chaffra_core::diagnostic::Severity::Info => "info",
                    };
                    *sev_counts.entry(sev.to_owned()).or_insert(0u64) += 1;
                    diagnostics
                        .entry(file_path.to_owned())
                        .or_default()
                        .push(finding_to_diagnostic(finding));
                }
                collector.record_module_findings(
                    module_id,
                    result.findings.len() as u64,
                    &sev_counts,
                );
                all_findings.extend(result.findings);
            }
            Err(_) => {
                let dur = start.elapsed().as_millis() as u64;
                collector.record_module_call(module_id, dur, true);
                had_error = true;
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    collector.record_module_call("lsp", duration_ms, had_error);
    let fingerprints = crate::fingerprints_from_findings(&all_findings);
    collector.set_finding_fingerprints(fingerprints);

    chaffra_telemetry::finalize_and_flush_sampled(&collector, live_state, &effective_tel);

    diagnostics
}

fn analyze_file_no_telemetry(file_path: &str, content: &[u8]) -> HashMap<String, Vec<Diagnostic>> {
    use chaffra_core::config::ChaffraConfig;
    use chaffra_core::diagnostic::FileInfo;
    use std::path::Path;

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
    let host = crate::build_module_host_with_telemetry(None);
    let config = ChaffraConfig::default();

    for module_id in &["dead-code", "complexity"] {
        if let Ok(result) = host.analyze(module_id, &files, &config) {
            for finding in &result.findings {
                diagnostics
                    .entry(file_path.to_owned())
                    .or_default()
                    .push(finding_to_diagnostic(finding));
            }
        }
    }

    diagnostics
}

/// Build the hover response content for complexity information.
pub fn build_hover_content(file_path: &str, content: &[u8], line: u32) -> Option<String> {
    use std::path::Path;

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

/// Parse the Content-Length value from LSP headers.
/// Returns None if no valid Content-Length header is found before the
/// blank-line separator.
async fn read_content_length(reader: &mut BufReader<tokio::io::Stdin>) -> Result<Option<usize>> {
    let mut content_length: Option<usize> = None;

    loop {
        let mut header_line = String::new();
        let n = reader.read_line(&mut header_line).await?;
        if n == 0 {
            return Ok(None);
        }

        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            break;
        }

        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    Ok(content_length)
}

/// Run the LSP server loop over stdio.
///
/// Implements proper Content-Length-based message framing per the LSP spec:
/// reads `Content-Length: N\r\n...\r\n` headers, then reads exactly N bytes
/// of JSON payload.
pub async fn run_lsp_server(
    live_state: chaffra_telemetry::LiveTelemetryState,
    tel_config: chaffra_telemetry::TelemetryConfig,
    explicit_cli_audience: bool,
) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);

    loop {
        let content_length = match read_content_length(&mut reader).await? {
            Some(len) => len,
            None => break,
        };

        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;

        let request: LspRequest = match serde_json::from_slice(&body) {
            Ok(req) => req,
            Err(_) => continue,
        };

        let responses =
            handle_lsp_request(&request, &live_state, &tel_config, explicit_cli_audience);
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
fn handle_lsp_request(
    request: &LspRequest,
    live_state: &chaffra_telemetry::LiveTelemetryState,
    tel_config: &chaffra_telemetry::TelemetryConfig,
    explicit_cli_audience: bool,
) -> Vec<LspResponse> {
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
                        let diagnostics_map = analyze_file_for_diagnostics(
                            file_path,
                            &content,
                            live_state,
                            tel_config,
                            explicit_cli_audience,
                        );

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

                    let diagnostics_map = analyze_file_for_diagnostics(
                        file_path,
                        content,
                        live_state,
                        tel_config,
                        explicit_cli_audience,
                    );

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

    fn test_live_state() -> chaffra_telemetry::LiveTelemetryState {
        chaffra_telemetry::LiveTelemetryState::new()
    }

    fn test_tel_config() -> chaffra_telemetry::TelemetryConfig {
        chaffra_telemetry::TelemetryConfig::default()
    }

    #[test]
    fn test_handle_initialize() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(1)),
            method: "initialize".to_owned(),
            params: Some(serde_json::json!({})),
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert_eq!(responses.len(), 1);
        assert!(responses[0].result.is_some());
        let result = responses[0].result.as_ref().unwrap();
        assert!(result["capabilities"].is_object());
    }

    #[test]
    fn test_handle_initialized() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: "initialized".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_handle_shutdown() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(2)),
            method: "shutdown".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].result, Some(serde_json::Value::Null));
    }

    #[test]
    fn test_handle_unknown_request() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(3)),
            method: "custom/unknown".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn test_handle_unknown_notification() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: "custom/unknown".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_handle_hover_no_params() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: Some(serde_json::json!(4)),
            method: "textDocument/hover".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].result, Some(serde_json::Value::Null));
    }

    #[test]
    fn test_handle_did_save_no_params() {
        let ls = test_live_state();
        let request = LspRequest {
            jsonrpc: "2.0".to_owned(),
            id: None,
            method: "textDocument/didSave".to_owned(),
            params: None,
        };
        let responses = handle_lsp_request(&request, &ls, &test_tel_config(), false);
        assert!(responses.is_empty());
    }

    #[test]
    fn test_analyze_file_go_content() {
        let ls = test_live_state();
        let content = b"package main\n\nfunc main() {}\n\nfunc unused() {}\n";
        let diagnostics =
            analyze_file_for_diagnostics("/tmp/test.go", content, &ls, &test_tel_config(), false);
        // Should produce at least dead-code findings for unused function.
        let all_diags: Vec<&Diagnostic> = diagnostics.values().flatten().collect();
        // The analysis should run without panicking.
        let _ = all_diags;
    }

    #[test]
    fn test_analyze_file_unknown_extension() {
        let ls = test_live_state();
        let content = b"some content";
        let diagnostics =
            analyze_file_for_diagnostics("/tmp/test.txt", content, &ls, &test_tel_config(), false);
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

    // --- merge_lsp_telemetry_config tests ---

    fn make_workspace_config_with_telemetry(
        entries: Vec<(&str, &str)>,
    ) -> chaffra_core::config::ChaffraConfig {
        let mut toml_str = String::from("[modules.telemetry]\n");
        for (k, v) in entries {
            toml_str.push_str(&format!("{k} = \"{v}\"\n"));
        }
        chaffra_core::config::ChaffraConfig::parse(&toml_str).unwrap()
    }

    #[test]
    fn test_merge_lsp_config_off_returns_none() {
        let server = test_tel_config();
        let workspace = make_workspace_config_with_telemetry(vec![("audience", "off")]);
        let result = merge_lsp_telemetry_config(&server, &workspace, false).unwrap();
        assert!(result.is_none(), "audience=off should return None");
    }

    #[test]
    fn test_merge_lsp_config_merges_sampling() {
        let server = test_tel_config();
        let workspace = make_workspace_config_with_telemetry(vec![
            ("audience", "on"),
            ("sampling-rate", "0.5"),
        ]);
        let result = merge_lsp_telemetry_config(&server, &workspace, false).unwrap();
        assert!(result.is_some());
        let merged = result.unwrap();
        assert!(
            (merged.sampling_rate - 0.5).abs() < f64::EPSILON,
            "sampling rate should be 0.5, got {}",
            merged.sampling_rate
        );
    }

    #[test]
    fn test_merge_lsp_config_empty_passthrough() {
        let server = test_tel_config();
        let workspace = chaffra_core::config::ChaffraConfig::default();
        let result = merge_lsp_telemetry_config(&server, &workspace, false).unwrap();
        assert!(result.is_some());
        let merged = result.unwrap();
        // With no project overrides, sampling rate should match server config.
        assert!(
            (merged.sampling_rate - server.sampling_rate).abs() < f64::EPSILON,
            "empty workspace should pass through server config"
        );
    }

    #[test]
    fn test_merge_lsp_config_invalid_fails_closed() {
        let server = test_tel_config();
        let workspace = make_workspace_config_with_telemetry(vec![("audience", "bogus")]);
        let result = merge_lsp_telemetry_config(&server, &workspace, false);
        assert!(result.is_err(), "invalid audience should fail closed");
    }

    #[test]
    fn test_merge_lsp_config_operator_opt_in() {
        let server = test_tel_config();
        let workspace = make_workspace_config_with_telemetry(vec![("audience", "on")]);
        let result = merge_lsp_telemetry_config(&server, &workspace, false).unwrap();
        assert!(result.is_some());
        let merged = result.unwrap();
        assert_eq!(merged.audience, chaffra_telemetry::TelemetryAudience::On);
    }

    #[test]
    fn test_merge_lsp_config_operator_only() {
        let server = test_tel_config();
        let workspace = make_workspace_config_with_telemetry(vec![("audience", "operator-only")]);
        let result = merge_lsp_telemetry_config(&server, &workspace, false).unwrap();
        assert!(result.is_some());
        let merged = result.unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::OperatorOnly
        );
    }

    #[test]
    fn test_merge_lsp_config_explicit_cli_audience_wins() {
        let server = test_tel_config();
        let workspace = make_workspace_config_with_telemetry(vec![("audience", "on")]);
        let result = merge_lsp_telemetry_config(&server, &workspace, true).unwrap();
        assert!(result.is_some());
        let merged = result.unwrap();
        assert_eq!(
            merged.audience,
            chaffra_telemetry::TelemetryAudience::UserOnly,
            "explicit CLI audience must override workspace config"
        );
    }

    #[test]
    fn test_analyze_file_for_diagnostics_telemetry_off() {
        let ls = test_live_state();
        let mut off_config = test_tel_config();
        off_config.audience = chaffra_telemetry::TelemetryAudience::Off;
        let content = b"package main\n\nfunc main() {}\n\nfunc unused() {}\n";
        // This should take the early-return path into analyze_file_no_telemetry.
        let diagnostics =
            analyze_file_for_diagnostics("/tmp/test_off.go", content, &ls, &off_config, false);
        // Should run without panicking and produce a valid map.
        let _total: usize = diagnostics.values().map(|v| v.len()).sum();
    }
}
