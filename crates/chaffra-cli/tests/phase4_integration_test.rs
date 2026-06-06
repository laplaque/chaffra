//! Integration tests for Phase 4: MCP, LSP mapping, badge output, types crate.

use chaffra_core::diagnostic::FileInfo;
use chaffra_core::module::AnalysisModule;
use chaffra_mcp::McpServer;
use std::collections::HashMap;
use std::path::Path;

fn load_fixture_files(fixture_dir: &str) -> Vec<FileInfo> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(fixture_dir);
    let discovered = chaffra_parse::discovery::discover_files(&root, &[]);
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

// --- MCP server integration tests ---

#[test]
fn test_mcp_full_session() {
    let mut server = McpServer::new();

    // Initialize.
    let resp = server
        .handle_message(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}"#,
        )
        .unwrap();
    assert!(resp.result.is_some());
    assert!(resp.error.is_none());

    // Initialized notification -- no response.
    let resp = server.handle_message(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    assert!(resp.is_none());

    // List tools.
    let resp = server
        .handle_message(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#)
        .unwrap();
    let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
    assert_eq!(tools.len(), 4);
    let tool_names: Vec<String> = tools
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(tool_names.contains(&"chaffra/health".to_owned()));
    assert!(tool_names.contains(&"chaffra/dead-code".to_owned()));
    assert!(tool_names.contains(&"chaffra/explain".to_owned()));
    assert!(tool_names.contains(&"chaffra/telemetry".to_owned()));

    // Call explain tool.
    let resp = server
        .handle_message(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"chaffra/explain","arguments":{"rule_id":"dead-code:unused-function"}}}"#,
        )
        .unwrap();
    let result = resp.result.unwrap();
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("unused"));

    // Shutdown.
    let resp = server
        .handle_message(r#"{"jsonrpc":"2.0","id":4,"method":"shutdown"}"#)
        .unwrap();
    assert!(resp.error.is_none());
}

#[test]
fn test_mcp_health_on_fixture() {
    let mut server = McpServer::new();

    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go/simple")
        .canonicalize()
        .unwrap();
    let msg = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"chaffra/health","arguments":{{"path":"{}"}}}}}}"#,
        fixture_path.display()
    );
    let resp = server.handle_message(&msg).unwrap();
    let result = resp.result.unwrap();
    let text = result["content"][0]["text"].as_str().unwrap();

    // Parse the health JSON from the tool result.
    let health: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(health["score"].as_u64().unwrap() > 0);
    assert!(health["total_files"].as_u64().unwrap() > 0);
}

#[test]
fn test_mcp_dead_code_on_fixture() {
    let mut server = McpServer::new();

    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go/simple")
        .canonicalize()
        .unwrap();
    let msg = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"chaffra/dead-code","arguments":{{"path":"{}"}}}}}}"#,
        fixture_path.display()
    );
    let resp = server.handle_message(&msg).unwrap();
    let result = resp.result.unwrap();
    let text = result["content"][0]["text"].as_str().unwrap();

    // Parse the analysis result JSON.
    let analysis: serde_json::Value = serde_json::from_str(text).unwrap();
    assert!(analysis["findings"].is_array());
    let findings = analysis["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "should find dead code in fixture");

    // Should find unused function.
    let has_unused = findings
        .iter()
        .any(|f| f["rule_id"].as_str() == Some("unused-function"));
    assert!(has_unused, "should find unused-function finding");
}

// --- Badge output integration tests ---

#[test]
fn test_badge_output_health() {
    let files = load_fixture_files("go/simple");
    assert!(!files.is_empty());

    let health = chaffra_complexity::analyze_project_health(&files, 20, 15).unwrap();
    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Badge);
    let badge_json = formatter.format_health(&health);

    let parsed: serde_json::Value = serde_json::from_str(&badge_json).unwrap();
    assert_eq!(parsed["schemaVersion"], 1);
    assert_eq!(parsed["label"], "chaffra health");
    assert!(parsed["message"].as_str().unwrap().ends_with('%'));
    let color = parsed["color"].as_str().unwrap();
    assert!(
        ["green", "yellow", "red"].contains(&color),
        "unexpected color: {color}"
    );
}

#[test]
fn test_badge_output_findings() {
    let module = chaffra_deadcode::DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Badge);
    let badge_json = formatter.format_findings(&result.findings);

    let parsed: serde_json::Value = serde_json::from_str(&badge_json).unwrap();
    assert_eq!(parsed["schemaVersion"], 1);
    assert!(parsed["color"].is_string());
}

// --- Types crate integration tests ---

#[test]
fn test_types_badge_response() {
    let badge = chaffra_types::BadgeResponse::from_health_score(85);
    assert_eq!(badge.color, "green");
    assert_eq!(badge.message, "85%");

    let json = serde_json::to_string(&badge).unwrap();
    let roundtrip: chaffra_types::BadgeResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(badge, roundtrip);
}

#[test]
fn test_types_finding_serialization() {
    let finding = chaffra_types::Finding {
        rule_id: "unused-function".to_owned(),
        message: "test".to_owned(),
        severity: chaffra_types::Severity::Warning,
        location: chaffra_types::Location {
            file: "test.go".to_owned(),
            start_line: 1,
            end_line: 5,
            start_column: 0,
            end_column: 0,
        },
        confidence: 1.0,
        actions: vec![],
        metadata: HashMap::new(),
    };
    let json = serde_json::to_string(&finding).unwrap();
    let roundtrip: chaffra_types::Finding = serde_json::from_str(&json).unwrap();
    assert_eq!(finding, roundtrip);
}

#[test]
fn test_types_health_grade_boundary_values() {
    let cases = vec![
        (100, chaffra_types::HealthGrade::A),
        (90, chaffra_types::HealthGrade::A),
        (89, chaffra_types::HealthGrade::B),
        (80, chaffra_types::HealthGrade::B),
        (79, chaffra_types::HealthGrade::C),
        (70, chaffra_types::HealthGrade::C),
        (69, chaffra_types::HealthGrade::D),
        (60, chaffra_types::HealthGrade::D),
        (59, chaffra_types::HealthGrade::F),
        (0, chaffra_types::HealthGrade::F),
    ];
    for (score, expected) in cases {
        assert_eq!(
            chaffra_types::HealthGrade::from_score(score),
            expected,
            "score: {score}"
        );
    }
}

// --- MCP error handling integration tests ---

#[test]
fn test_mcp_protocol_error_handling() {
    let mut server = McpServer::new();

    // Invalid JSON.
    let resp = server.handle_message("not json at all").unwrap();
    assert!(resp.error.is_some());
    assert_eq!(resp.error.as_ref().unwrap().code, -32700);

    // Unknown method with ID.
    let resp = server
        .handle_message(r#"{"jsonrpc":"2.0","id":1,"method":"foo/bar"}"#)
        .unwrap();
    assert!(resp.error.is_some());
    assert_eq!(resp.error.as_ref().unwrap().code, -32601);

    // Unknown notification (no ID) -- should return None.
    let resp = server.handle_message(r#"{"jsonrpc":"2.0","method":"notifications/unknown"}"#);
    assert!(resp.is_none());
}
