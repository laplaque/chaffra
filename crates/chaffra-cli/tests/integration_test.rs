//! Integration tests for chaffra modules.
//!
//! Tests use Go, Python, TypeScript, and Java fixtures under `tests/fixtures/`.

use chaffra_arch::ArchitectureModule;
use chaffra_complexity::{ComplexityModule, analyze_project_health};
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::{FileInfo, HealthGrade};
use chaffra_core::module::{AnalysisModule, ModuleHost};
use chaffra_deadcode::DeadCodeModule;
use chaffra_duplication::DuplicationModule;
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

#[test]
fn test_python_aliased_imports_not_flagged() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("python/aliases");
    assert!(!files.is_empty(), "should find Python alias fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    // `import numpy as np` with `np.array(...)` usage — should NOT be flagged.
    let flagged_np: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-import" && f.message.contains("numpy"))
        .collect();
    assert!(
        flagged_np.is_empty(),
        "import numpy as np should not be flagged when np is used"
    );

    // `from os.path import join as path_join` with `path_join(...)` usage — should NOT be flagged.
    let flagged_ospath: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-import" && f.message.contains("os.path"))
        .collect();
    assert!(
        flagged_ospath.is_empty(),
        "from os.path import join as path_join should not be flagged when path_join is used"
    );

    // `import os` without any `os.` usage — SHOULD be flagged.
    let flagged_os: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-import" && f.message.contains("`os`"))
        .collect();
    assert!(
        !flagged_os.is_empty(),
        "bare import os should be flagged as unused"
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

// --- Phase 2: Duplication integration tests ---

#[test]
fn test_go_duplication_detects_clones() {
    let module = DuplicationModule::new();
    let files = load_fixture_files("go/clones");
    assert!(files.len() >= 2, "should find Go clone fixture files");

    let mut config = HashMap::new();
    config.insert("min-tokens".to_owned(), "10".to_owned());
    config.insert("mode".to_owned(), "mild".to_owned());

    let result = module.analyze(&files, &config).unwrap();
    assert!(
        !result.findings.is_empty(),
        "should detect duplicate blocks in handler_a.go / handler_b.go"
    );

    // Every finding should have a family_id.
    for finding in &result.findings {
        assert!(
            finding.metadata.contains_key("family_id"),
            "finding should have family_id"
        );
        assert!(
            finding.metadata["family_id"].starts_with("dup:"),
            "family_id should start with dup:"
        );
    }
}

#[test]
fn test_python_duplication_detects_clones() {
    let module = DuplicationModule::new();
    let files = load_fixture_files("python/clones");
    assert!(files.len() >= 2, "should find Python clone fixture files");

    let mut config = HashMap::new();
    config.insert("min-tokens".to_owned(), "10".to_owned());
    config.insert("mode".to_owned(), "mild".to_owned());

    let result = module.analyze(&files, &config).unwrap();
    assert!(
        !result.findings.is_empty(),
        "should detect duplicate blocks in processor_a.py / processor_b.py"
    );
}

#[test]
fn test_duplication_module_via_host() {
    let mut host = ModuleHost::new();
    host.register(Box::new(DuplicationModule::new())).unwrap();

    let files = load_fixture_files("go/clones");
    let config = ChaffraConfig::default();
    let result = host.analyze("duplication", &files, &config).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

#[test]
fn test_duplication_explain_rules() {
    let module = DuplicationModule::new();
    let explanation = module.explain("duplicate-block").unwrap();
    assert_eq!(explanation.rule_id, "duplicate-block");
    assert!(!explanation.description.is_empty());

    let explanation = module.explain("duplicate-function").unwrap();
    assert_eq!(explanation.rule_id, "duplicate-function");
}

// --- Phase 2: Architecture integration tests ---

#[test]
fn test_architecture_module_presets() {
    let module = ArchitectureModule::new();
    let info = module.describe();
    assert_eq!(info.id, "architecture");
    assert!(info.rules.len() >= 2);

    // Load preset configurations.
    for preset in &["layered", "hexagonal", "feature-sliced", "clean"] {
        let (zones, rules) = chaffra_arch::load_preset(preset);
        assert!(!zones.is_empty(), "preset {preset} should have zones");
        assert!(!rules.is_empty(), "preset {preset} should have rules");
    }
}

#[test]
fn test_architecture_analyze_boundaries() {
    let module = ArchitectureModule::new();
    let files = load_fixture_files("go/boundaries");
    assert!(!files.is_empty(), "should find Go boundary fixture files");

    let mut config = HashMap::new();
    config.insert("preset".to_owned(), "layered".to_owned());

    let result = module.analyze(&files, &config).unwrap();
    // Even if no violations are found, the analysis should succeed.
    assert!(result.metrics.files_analyzed > 0);
}

#[test]
fn test_architecture_module_via_host() {
    let mut host = ModuleHost::new();
    host.register(Box::new(ArchitectureModule::new())).unwrap();

    let files = load_fixture_files("go/boundaries");
    let toml = r#"
[modules.architecture]
preset = "layered"
"#;
    let config = ChaffraConfig::parse(toml).unwrap();
    let result = host.analyze("architecture", &files, &config).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

#[test]
fn test_architecture_explain_rules() {
    let module = ArchitectureModule::new();
    let explanation = module.explain("boundary-violation").unwrap();
    assert_eq!(explanation.rule_id, "boundary-violation");
    assert!(!explanation.description.is_empty());

    let explanation = module.explain("circular-dependency").unwrap();
    assert_eq!(explanation.rule_id, "circular-dependency");
}

// --- Phase 2: SARIF output integration test ---

#[test]
fn test_sarif_output_valid() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Sarif);
    let sarif_str = formatter.format_findings(&result.findings);

    let parsed: serde_json::Value = serde_json::from_str(&sarif_str).unwrap();
    assert_eq!(parsed["version"], "2.1.0");
    assert!(parsed["$schema"].as_str().unwrap().contains("sarif"));
    assert!(parsed["runs"][0]["results"].as_array().is_some());
}

// --- Phase 2: TypeScript/JavaScript fixture tests ---

#[test]
fn test_typescript_dead_code() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("typescript/simple");
    assert!(!files.is_empty(), "should find TypeScript fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();
    // Should find unused helper function.
    let unused_funcs: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-function")
        .collect();
    assert!(
        !unused_funcs.is_empty(),
        "should find unused TypeScript functions"
    );
}

#[test]
fn test_typescript_complexity() {
    let module = ComplexityModule::new();
    let files = load_fixture_files("typescript/simple");
    assert!(!files.is_empty());

    let result = module.analyze(&files, &HashMap::new()).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

// --- Phase 2: Java fixture tests ---

#[test]
fn test_java_dead_code() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("java/simple");
    assert!(!files.is_empty(), "should find Java fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

#[test]
fn test_java_complexity() {
    let module = ComplexityModule::new();
    let files = load_fixture_files("java/simple");
    assert!(!files.is_empty());

    let result = module.analyze(&files, &HashMap::new()).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

// --- Phase 2: Full module host with all 4 modules ---

#[test]
fn test_full_module_host_registration() {
    let mut host = ModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();
    host.register(Box::new(DuplicationModule::new())).unwrap();
    host.register(Box::new(ArchitectureModule::new())).unwrap();

    let modules = host.list();
    assert_eq!(modules.len(), 4);

    let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"dead-code"));
    assert!(ids.contains(&"complexity"));
    assert!(ids.contains(&"duplication"));
    assert!(ids.contains(&"architecture"));
}
