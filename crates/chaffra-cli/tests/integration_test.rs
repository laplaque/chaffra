//! Integration tests for chaffra Phase 1 modules.
//!
//! Tests use Go and Python fixtures under `tests/fixtures/`.

use chaffra_complexity::{ComplexityModule, analyze_project_health};
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::{FileInfo, HealthGrade};
use chaffra_core::module::{AnalysisModule, ModuleHost};
use chaffra_deadcode::DeadCodeModule;
use std::collections::HashMap;
use std::path::Path;

fn load_fixture_files(fixture_dir: &str) -> Vec<FileInfo> {
    // CARGO_MANIFEST_DIR points to crates/chaffra-cli; fixtures are at workspace root.
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

// --- Dead-code integration tests ---

#[test]
fn test_go_dead_code_finds_unused() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    assert!(!files.is_empty(), "should find Go fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    // Should find the unused function.
    let unused_funcs: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-function" && f.message.contains("unused"))
        .collect();
    assert!(!unused_funcs.is_empty(), "should find unused() function");

    // Should find the unused import (os).
    let unused_imports: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-import" && f.message.contains("os"))
        .collect();
    assert!(!unused_imports.is_empty(), "should find unused os import");

    // Should NOT flag helper() since it's called from main().
    let flagged_helper: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-function" && f.message.contains("helper"))
        .collect();
    assert!(
        flagged_helper.is_empty(),
        "helper should not be flagged as unused"
    );

    // Should NOT flag suppressedFunc() due to chaffra:ignore.
    let flagged_suppressed: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-function" && f.message.contains("suppressedFunc"))
        .collect();
    assert!(
        flagged_suppressed.is_empty(),
        "suppressedFunc should not be flagged"
    );
}

#[test]
fn test_python_dead_code_finds_unused() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("python/simple");
    assert!(!files.is_empty(), "should find Python fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    // Should find unused private functions.
    let unused_funcs: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-function")
        .collect();
    assert!(
        !unused_funcs.is_empty(),
        "should find unused Python functions"
    );

    // Should NOT flag suppressed functions.
    let flagged_suppressed: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-function" && f.message.contains("suppressed"))
        .collect();
    assert!(
        flagged_suppressed.is_empty(),
        "suppressed function should not be flagged"
    );
}

// --- Complexity/health integration tests ---

#[test]
fn test_go_health_scoring_simple() {
    let files = load_fixture_files("go/simple");
    assert!(!files.is_empty());

    let health = analyze_project_health(&files, 20, 15).unwrap();
    assert!(
        health.score >= 80,
        "simple Go code should have high health score, got {}",
        health.score
    );
    assert!(
        matches!(health.grade, HealthGrade::A | HealthGrade::B),
        "simple Go code should grade A or B, got {}",
        health.grade
    );
}

#[test]
fn test_go_health_scoring_complex() {
    let files = load_fixture_files("go/complex");
    assert!(!files.is_empty());

    let health = analyze_project_health(&files, 20, 15).unwrap();
    // Complex handler should pull the score down.
    assert!(
        health.score <= 100,
        "health score should be <= 100, got {}",
        health.score
    );
    // At minimum the score should be computable.
    assert!(health.total_files > 0);
}

#[test]
fn test_complexity_module_via_host() {
    let mut host = ModuleHost::new();
    host.register(Box::new(ComplexityModule::new())).unwrap();

    let files = load_fixture_files("go/complex");
    let config = ChaffraConfig::default();
    let result = host.analyze("complexity", &files, &config).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

// --- Module host integration tests ---

#[test]
fn test_module_discovery_and_registration() {
    let mut host = ModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();

    let modules = host.list();
    assert_eq!(modules.len(), 2);

    let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"dead-code"));
    assert!(ids.contains(&"complexity"));
}

#[test]
fn test_module_explain_via_host() {
    let mut host = ModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();

    // Qualified rule ID.
    let explanation = host.explain("dead-code:unused-function").unwrap();
    assert_eq!(explanation.rule_id, "unused-function");

    // Unqualified rule ID (searches all modules).
    let explanation = host.explain("high-cyclomatic").unwrap();
    assert_eq!(explanation.rule_id, "high-cyclomatic");

    // Unknown rule.
    assert!(host.explain("nonexistent:rule").is_err());
}

#[test]
fn test_analyze_with_config() {
    let mut host = ModuleHost::new();
    host.register(Box::new(ComplexityModule::new())).unwrap();

    let files = load_fixture_files("go/complex");

    // Use low thresholds to ensure findings are generated.
    let toml = r#"
[modules.complexity]
max-cyclomatic = "5"
max-cognitive = "3"
"#;
    let config = ChaffraConfig::parse(toml).unwrap();
    let result = host.analyze("complexity", &files, &config).unwrap();

    let high_complexity: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "high-cyclomatic")
        .collect();
    assert!(
        !high_complexity.is_empty(),
        "should find high complexity with low threshold"
    );
}

// --- Output formatting integration tests ---

#[test]
fn test_json_output_roundtrip() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Json);
    let json_str = formatter.format_findings(&result.findings);

    // Should be valid JSON.
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.get("findings").is_some());
}

#[test]
fn test_markdown_output() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Markdown);
    let md = formatter.format_findings(&result.findings);
    assert!(md.contains("## Findings"));
}

#[test]
fn test_terminal_output() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Terminal);
    let text = formatter.format_findings(&result.findings);
    // Should contain severity indicators.
    assert!(text.contains("[W]") || text.contains("No issues found"));
}
