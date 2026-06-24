//! Integration tests for chaffra modules (Phase 1 + Phase 8 + Phase 9).
//!
//! Tests use Go and Python fixtures under `tests/fixtures/`.

use chaffra_autofix::{AutofixModule, apply_fixes_to_files, collect_fixable, orchestrate_fixes};
use chaffra_complexity::{ComplexityModule, analyze_project_health};
use chaffra_core::config::ChaffraConfig;
use chaffra_core::diagnostic::{FileInfo, HealthGrade};
use chaffra_core::grpc::GrpcModuleHost;
use chaffra_core::module::AnalysisModule;
use chaffra_deadcode::DeadCodeModule;
use chaffra_frameworks::FrameworksModule;
use chaffra_tui::App;
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
    let mut host = GrpcModuleHost::new();
    host.register(Box::new(ComplexityModule::new())).unwrap();

    let files = load_fixture_files("go/complex");
    let config = ChaffraConfig::default();
    let result = host.analyze("complexity", &files, &config).unwrap();
    assert_eq!(result.metrics.files_analyzed, files.len() as u64);
}

// --- Module host integration tests ---

#[test]
fn test_module_discovery_and_registration() {
    let mut host = GrpcModuleHost::new();
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
    let mut host = GrpcModuleHost::new();
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
    let mut host = GrpcModuleHost::new();
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

// --- Framework detection integration tests ---

#[test]
fn test_gin_framework_detection() {
    let module = FrameworksModule::new();
    let files = load_fixture_files("go/gin");
    assert!(!files.is_empty(), "should find gin fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    // Should detect gin entry points.
    let entry_points: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-entry-point")
        .collect();
    assert!(
        entry_points.len() >= 4,
        "should detect multiple gin handlers: {entry_points:?}"
    );
    assert!(
        entry_points
            .iter()
            .all(|f| f.metadata.get("framework").map_or(false, |v| v == "gin")),
        "all entries should be gin framework"
    );

    // Should detect the gin framework.
    let framework_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-detected")
        .collect();
    assert!(
        framework_findings.iter().any(|f| f.message.contains("gin")),
        "should detect gin framework"
    );
}

#[test]
fn test_echo_framework_detection() {
    let module = FrameworksModule::new();
    let files = load_fixture_files("go/echo");
    assert!(!files.is_empty(), "should find echo fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let entry_points: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-entry-point")
        .collect();
    assert!(
        entry_points.len() >= 2,
        "should detect echo handlers: {entry_points:?}"
    );
    assert!(
        entry_points
            .iter()
            .all(|f| f.metadata.get("framework").map_or(false, |v| v == "echo")),
        "all entries should be echo framework"
    );
}

#[test]
fn test_cobra_framework_detection() {
    let module = FrameworksModule::new();
    let files = load_fixture_files("go/cobra");
    assert!(!files.is_empty(), "should find cobra fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let entry_points: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-entry-point")
        .collect();
    assert!(
        !entry_points.is_empty(),
        "should detect cobra commands: {entry_points:?}"
    );
    assert!(
        entry_points
            .iter()
            .all(|f| f.metadata.get("framework").map_or(false, |v| v == "cobra")),
        "all entries should be cobra framework"
    );
}

#[test]
fn test_fastapi_framework_detection() {
    let module = FrameworksModule::new();
    let files = load_fixture_files("python/fastapi");
    assert!(!files.is_empty(), "should find FastAPI fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let entry_points: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-entry-point")
        .collect();
    assert!(
        entry_points.len() >= 4,
        "should detect FastAPI routes: {entry_points:?}"
    );
    assert!(
        entry_points.iter().all(|f| f
            .metadata
            .get("framework")
            .map_or(false, |v| v == "fastapi")),
        "all entries should be fastapi framework"
    );
}

#[test]
fn test_django_framework_detection() {
    let module = FrameworksModule::new();
    let files = load_fixture_files("python/django");
    assert!(!files.is_empty(), "should find Django fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    // Should detect class-based views and URL patterns.
    let entry_points: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-entry-point")
        .collect();
    assert!(
        !entry_points.is_empty(),
        "should detect Django views or URL patterns: {entry_points:?}"
    );
    assert!(
        entry_points
            .iter()
            .all(|f| f.metadata.get("framework").map_or(false, |v| v == "django")),
        "all entries should be django framework"
    );
}

#[test]
fn test_flask_framework_detection() {
    let module = FrameworksModule::new();
    let files = load_fixture_files("python/flask");
    assert!(!files.is_empty(), "should find Flask fixture files");

    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let entry_points: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "framework-entry-point")
        .collect();
    assert!(
        entry_points.len() >= 3,
        "should detect Flask routes: {entry_points:?}"
    );
    assert!(
        entry_points
            .iter()
            .all(|f| f.metadata.get("framework").map_or(false, |v| v == "flask")),
        "all entries should be flask framework"
    );
}

#[test]
fn test_frameworks_module_registration() {
    let mut host = GrpcModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();
    host.register(Box::new(FrameworksModule::new())).unwrap();

    let modules = host.list();
    assert_eq!(modules.len(), 3);

    let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"frameworks"));
}

#[test]
fn test_frameworks_explain_via_host() {
    let mut host = GrpcModuleHost::new();
    host.register(Box::new(FrameworksModule::new())).unwrap();

    let explanation = host.explain("frameworks:framework-entry-point").unwrap();
    assert_eq!(explanation.rule_id, "framework-entry-point");
    assert!(!explanation.examples.is_empty());
}

#[test]
fn test_alive_entry_points_utility() {
    let files = load_fixture_files("go/gin");
    let entries = chaffra_frameworks::get_alive_entry_points(&files);
    assert!(
        !entries.is_empty(),
        "should return alive entry points for gin fixtures"
    );
    assert!(entries.iter().all(|e| e.framework == "gin"));
}

#[test]
fn test_grpc_client_mock_connection_failure() {
    // Verify the gRPC client gracefully handles connection failures.
    use chaffra_plugin::config::{ExternalModuleConfig, TransportMode};
    use chaffra_plugin::host::ExternalModule;

    let config = ExternalModuleConfig {
        id: "test-external".to_owned(),
        mode: TransportMode::Grpc,
        command: None,
        endpoint: Some("http://127.0.0.1:59999".to_owned()),
        image: None,
        port: None,
    };
    let module = ExternalModule::new(config);

    // describe() should fall back to config-based info.
    let info = module.describe();
    assert_eq!(info.id, "test-external");
    assert!(info.name.contains("external"));

    // analyze() should return an error.
    let result = module.analyze(&[], &HashMap::new());
    assert!(result.is_err());
}

#[test]
fn test_external_module_config_parsing() {
    use chaffra_plugin::config::{TransportMode, parse_external_modules};

    let toml = r#"
[[external_modules]]
id = "gin"
command = "chaffra-module-gin"

[[external_modules]]
id = "fastapi"
mode = "grpc"
endpoint = "http://localhost:50051"

[[external_modules]]
id = "django"
mode = "container"
image = "chaffra/module-django:latest"
port = 50052
"#;
    let modules = parse_external_modules(toml).unwrap();
    assert_eq!(modules.len(), 3);

    assert_eq!(modules[0].id, "gin");
    assert_eq!(modules[0].mode, TransportMode::Command);

    assert_eq!(modules[1].id, "fastapi");
    assert_eq!(modules[1].mode, TransportMode::Grpc);

    assert_eq!(modules[2].id, "django");
    assert_eq!(modules[2].mode, TransportMode::Container);
    assert_eq!(modules[2].port, Some(50052));
}

// --- Phase 8: Autofix integration tests ---

#[test]
fn test_autofix_module_registration() {
    let mut host = GrpcModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();
    host.register(Box::new(AutofixModule::new())).unwrap();

    let modules = host.list();
    assert_eq!(modules.len(), 3);

    let ids: Vec<&str> = modules.iter().map(|m| m.id.as_str()).collect();
    assert!(ids.contains(&"autofix"));
}

#[test]
fn test_autofix_explain_rules() {
    let mut host = GrpcModuleHost::new();
    host.register(Box::new(AutofixModule::new())).unwrap();

    let cases = vec!["fix-applied", "fix-conflict", "fix-skipped"];
    for rule_id in cases {
        let explanation = host.explain(&format!("autofix:{rule_id}")).unwrap();
        assert_eq!(explanation.rule_id, rule_id);
        assert!(!explanation.description.is_empty());
    }
}

#[test]
fn test_autofix_collect_fixable_from_dead_code() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let fixable = collect_fixable(&result.findings);
    // There should be fixable findings (unused function, unused import, etc.)
    assert!(
        !fixable.is_empty(),
        "dead-code module should produce fixable findings"
    );

    // All fixable findings should have auto_fixable actions.
    for finding in &fixable {
        assert!(
            finding.actions.iter().any(|a| a.auto_fixable),
            "fixable finding should have an auto_fixable action"
        );
    }
}

#[test]
fn test_autofix_dry_run_on_real_findings() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let fixable: Vec<_> = collect_fixable(&result.findings)
        .into_iter()
        .cloned()
        .collect();
    if fixable.is_empty() {
        return; // No fixable findings; skip.
    }

    let results = orchestrate_fixes(&fixable, true).unwrap();
    assert_eq!(results.len(), fixable.len());

    // All should be dry-run (not applied).
    for r in &results {
        assert!(!r.applied, "dry run should not apply fixes");
        assert!(
            r.reason == "dry run" || r.reason.contains("overlapping"),
            "unexpected reason: {}",
            r.reason
        );
    }
}

#[test]
fn test_autofix_apply_to_content() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    // Get one fixable finding for unused import.
    let unused_imports: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.rule_id == "unused-import")
        .cloned()
        .collect();
    if unused_imports.is_empty() {
        return;
    }

    let fix_results = orchestrate_fixes(&unused_imports, false).unwrap();

    // Build file contents from fixtures.
    let mut file_contents = HashMap::new();
    for file in &files {
        let content = String::from_utf8_lossy(&file.content).to_string();
        file_contents.insert(file.path.clone(), content);
    }

    let new_contents = apply_fixes_to_files(&file_contents, &fix_results);

    // If any fixes were applied, the file content should be different.
    let any_applied = fix_results.iter().any(|r| r.applied);
    if any_applied {
        assert!(
            !new_contents.is_empty(),
            "applied fixes should produce new content"
        );
    }
}

#[test]
fn test_autofix_conflict_detection() {
    use chaffra_core::diagnostic::{Action, Finding, Location, Severity, TextEdit};

    // Create two findings that overlap in the same file.
    let findings = vec![
        Finding {
            rule_id: "rule-a".to_owned(),
            message: "finding a".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 5,
                end_line: 10,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![Action {
                description: "fix a".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "test.go".to_owned(),
                    start_line: 5,
                    end_line: 10,
                    new_text: String::new(),
                }],
            }],
            metadata: HashMap::new(),
        },
        Finding {
            rule_id: "rule-b".to_owned(),
            message: "finding b".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 8,
                end_line: 12,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![Action {
                description: "fix b".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "test.go".to_owned(),
                    start_line: 8,
                    end_line: 12,
                    new_text: String::new(),
                }],
            }],
            metadata: HashMap::new(),
        },
    ];

    let results = orchestrate_fixes(&findings, false).unwrap();
    assert_eq!(results.len(), 2);
    // Both should be skipped due to conflict.
    assert!(!results[0].applied);
    assert!(!results[1].applied);
    assert!(results[0].reason.contains("overlapping"));
    assert!(results[1].reason.contains("overlapping"));
}

// --- Phase 8: Hooks integration tests ---

#[test]
fn test_hooks_install_and_uninstall() {
    use chaffra_autofix::hooks;
    use tempfile::TempDir;

    let repo = TempDir::new().unwrap();
    let hooks_dir = repo.path().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).unwrap();

    // Install.
    let result = hooks::install_hook(repo.path()).unwrap();
    assert_eq!(result, hooks::HookResult::Installed);
    assert!(hooks::is_hook_installed(repo.path()));

    // Idempotent.
    let result = hooks::install_hook(repo.path()).unwrap();
    assert_eq!(result, hooks::HookResult::AlreadyInstalled);

    // Uninstall.
    let result = hooks::uninstall_hook(repo.path()).unwrap();
    assert_eq!(result, hooks::HookResult::Uninstalled);
    assert!(!hooks::is_hook_installed(repo.path()));
}

// --- Phase 8: TUI integration tests ---

#[test]
fn test_tui_app_with_real_findings() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let app = App::new(result.findings.clone());
    assert_eq!(app.visible_count(), result.findings.len());

    // Grouped by file should have entries.
    let groups = app.grouped_findings();
    assert!(!groups.is_empty());
}

#[test]
fn test_tui_navigation_with_findings() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let mut app = App::new(result.findings);
    assert_eq!(app.selected, 0);

    app.handle_key('j'); // Move down.
    if app.visible_count() > 1 {
        assert_eq!(app.selected, 1);
    }

    app.handle_key('G'); // Move to end.
    assert_eq!(app.selected, app.visible_count().saturating_sub(1));

    app.handle_key('g'); // Move to top.
    assert_eq!(app.selected, 0);
}

#[test]
fn test_tui_severity_filtering() {
    use chaffra_core::diagnostic::Severity;

    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let mut app = App::new(result.findings);
    let total = app.visible_count();

    // Toggle off info severity.
    app.toggle_severity(Severity::Info);
    let after_toggle = app.visible_count();
    assert!(after_toggle <= total);

    // Toggle it back on.
    app.toggle_severity(Severity::Info);
    assert_eq!(app.visible_count(), total);
}

#[test]
fn test_tui_grouping_modes() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let mut app = App::new(result.findings);

    // Default: group by file.
    let by_file_count = app.grouped_findings().len();

    // Cycle to rule.
    app.cycle_group();
    let by_rule_count = app.grouped_findings().len();

    // Cycle to severity.
    app.cycle_group();
    let by_severity_count = app.grouped_findings().len();

    // Different groupings should produce groups.
    assert!(by_file_count > 0);
    assert!(by_rule_count > 0);
    assert!(by_severity_count > 0);
}

#[test]
fn test_tui_fix_action() {
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    let mut app = App::new(result.findings);

    // Navigate to a fixable finding and press 'f'.
    let fixable_idx = app
        .visible_findings()
        .iter()
        .position(|f| f.actions.iter().any(|a| a.auto_fixable));

    if let Some(idx) = fixable_idx {
        app.selected = idx;
        app.handle_key('f');
        assert!(!app.pending_actions.is_empty(), "should queue a fix action");
    }
}

// --- Phase 8: Regression tests for P1 fixes ---

#[test]
fn test_fix_command_includes_complexity_findings() {
    // Regression: cmd_fix must analyze both dead-code and complexity modules,
    // not just dead-code. Verify that the module host can produce complexity
    // findings that would be included in a fix pass.
    let mut host = GrpcModuleHost::new();
    host.register(Box::new(DeadCodeModule::new())).unwrap();
    host.register(Box::new(ComplexityModule::new())).unwrap();

    let files = load_fixture_files("go/complex");
    let config_toml = r#"
[modules.complexity]
max-cyclomatic = "5"
max-cognitive = "3"
"#;
    let config = chaffra_core::config::ChaffraConfig::parse(config_toml).unwrap();

    let dead_code_result = host.analyze("dead-code", &files, &config).unwrap();
    let complexity_result = host.analyze("complexity", &files, &config).unwrap();

    let mut all_findings = dead_code_result.findings;
    all_findings.extend(complexity_result.findings);

    // The combined findings should include complexity rules (high-cyclomatic
    // or high-cognitive) in addition to any dead-code rules.
    let complexity_findings: Vec<_> = all_findings
        .iter()
        .filter(|f| f.rule_id.starts_with("high-"))
        .collect();
    assert!(
        !complexity_findings.is_empty(),
        "fix pass should include complexity findings with low thresholds"
    );
}

#[test]
fn test_hook_script_scopes_to_staged_files_integration() {
    // Regression: the pre-commit hook must pass staged file paths to the
    // analysis command, not run over the entire repo.
    let script = chaffra_autofix::hooks::hook_script();
    assert!(
        script.contains("for file in $STAGED"),
        "hook must iterate staged files individually"
    );
    assert!(
        script.contains("chaffra dead-code \"$file\""),
        "hook must pass each staged file to chaffra dead-code"
    );
    assert!(
        !script.contains("chaffra dead-code ."),
        "hook must NOT scan the entire repo"
    );
}

#[test]
fn test_tui_grouped_selection_alignment_integration() {
    // Regression: when findings are grouped (e.g. by severity), the selected
    // index must map to the same finding in both the render list and the
    // action handlers.
    let module = DeadCodeModule::new();
    let files = load_fixture_files("go/simple");
    let result = module.analyze(&files, &HashMap::new()).unwrap();

    if result.findings.len() < 2 {
        return; // Need multiple findings to test grouping.
    }

    let mut app = App::new(result.findings);
    app.group_by = chaffra_tui::GroupBy::Severity;

    let count = app.grouped_flat_findings().len();
    assert!(count >= 2, "need at least 2 findings for grouping test");

    // Capture expected location from the last finding *before* mutating app.
    let expected_loc = {
        let flat = app.grouped_flat_findings();
        let f = flat[count - 1];
        format!("{}:{}", f.location.file, f.location.start_line)
    };

    // Select the last finding and copy its location.
    app.selected = count - 1;
    let loc = app.copy_location();
    assert!(
        loc.is_some(),
        "should copy location for last grouped finding"
    );

    // The copied location must match the last finding in grouped flat order.
    assert_eq!(
        loc.unwrap(),
        expected_loc,
        "copied location must match the finding at the selected grouped index"
    );
}

// --- Wire-compatibility tests: chaffra_core ↔ chaffra_types ---

#[test]
fn test_wire_compat_finding_core_to_types() {
    let core_finding = chaffra_core::diagnostic::Finding {
        rule_id: "unused-function".to_owned(),
        message: "function `foo` is never used".to_owned(),
        severity: chaffra_core::diagnostic::Severity::Warning,
        location: chaffra_core::diagnostic::Location {
            file: "test.go".to_owned(),
            start_line: 5,
            end_line: 10,
            start_column: 0,
            end_column: 1,
        },
        confidence: 0.95,
        actions: vec![chaffra_core::diagnostic::Action {
            description: "Remove function".to_owned(),
            auto_fixable: true,
            edits: vec![chaffra_core::diagnostic::TextEdit {
                file: "test.go".to_owned(),
                start_line: 5,
                end_line: 10,
                new_text: String::new(),
            }],
        }],
        metadata: {
            let mut m = HashMap::new();
            m.insert("scope".to_owned(), "package".to_owned());
            m
        },
    };

    let json = serde_json::to_string(&core_finding).unwrap();
    let types_finding: chaffra_types::Finding = serde_json::from_str(&json).unwrap();

    assert_eq!(types_finding.rule_id, core_finding.rule_id);
    assert_eq!(types_finding.message, core_finding.message);
    assert_eq!(types_finding.confidence, core_finding.confidence);
    assert_eq!(types_finding.location.file, core_finding.location.file);
    assert_eq!(
        types_finding.location.start_line,
        core_finding.location.start_line
    );
    assert_eq!(types_finding.actions.len(), 1);
    assert_eq!(types_finding.actions[0].auto_fixable, true);
    assert_eq!(types_finding.metadata.get("scope").unwrap(), "package");
}

#[test]
fn test_wire_compat_finding_types_to_core() {
    let types_finding = chaffra_types::Finding {
        rule_id: "high-cyclomatic".to_owned(),
        message: "complexity too high".to_owned(),
        severity: chaffra_types::Severity::Error,
        location: chaffra_types::Location {
            file: "main.py".to_owned(),
            start_line: 1,
            end_line: 50,
            start_column: 0,
            end_column: 0,
        },
        confidence: 1.0,
        actions: vec![],
        metadata: HashMap::new(),
    };

    let json = serde_json::to_string(&types_finding).unwrap();
    let core_finding: chaffra_core::diagnostic::Finding = serde_json::from_str(&json).unwrap();

    assert_eq!(core_finding.rule_id, types_finding.rule_id);
    assert_eq!(core_finding.message, types_finding.message);
    assert_eq!(core_finding.location.file, types_finding.location.file);
}

#[test]
fn test_wire_compat_severity_values() {
    for (core_sev, label) in [
        (chaffra_core::diagnostic::Severity::Info, "\"info\""),
        (chaffra_core::diagnostic::Severity::Warning, "\"warning\""),
        (chaffra_core::diagnostic::Severity::Error, "\"error\""),
    ] {
        let core_json = serde_json::to_string(&core_sev).unwrap();
        assert_eq!(core_json, label);
        let types_sev: chaffra_types::Severity = serde_json::from_str(&core_json).unwrap();
        let types_json = serde_json::to_string(&types_sev).unwrap();
        assert_eq!(core_json, types_json);
    }
}

#[test]
fn test_wire_compat_health_grade_values() {
    for score in [100, 90, 85, 75, 65, 50, 0] {
        let core_grade = chaffra_core::diagnostic::HealthGrade::from_score(score);
        let types_grade = chaffra_types::HealthGrade::from_score(score);

        let core_json = serde_json::to_string(&core_grade).unwrap();
        let types_json = serde_json::to_string(&types_grade).unwrap();
        assert_eq!(core_json, types_json, "grade mismatch at score={score}");
    }
}

// --- Duplication module integration tests ---

fn make_duplication_files() -> Vec<FileInfo> {
    let block: String = (0..60)
        .map(|i| format!("    line{i} := doWork({i})\n"))
        .collect();
    let mut files = Vec::new();
    for i in 0..10 {
        let content = format!("package p{i}\n\nfunc F{i}() {{\n{block}}}\n");
        files.push(FileInfo {
            path: format!("pkg{i}/f.go"),
            content: content.into_bytes(),
        });
    }
    files
}

#[test]
fn test_duplication_grpc_roundtrip_bounded_output() {
    use chaffra_duplication::DuplicationModule;

    let mut host = GrpcModuleHost::new();
    host.register(Box::new(DuplicationModule::new())).unwrap();

    let files = make_duplication_files();

    let toml = r#"
[modules.duplication]
min-tokens = "15"
"#;
    let config = chaffra_core::config::ChaffraConfig::parse(toml).unwrap();
    let result = host.analyze("duplication", &files, &config).unwrap();

    assert!(
        !result.findings.is_empty(),
        "should produce duplication findings through gRPC"
    );
    assert!(
        result.findings.len() <= 200,
        "findings must be bounded by max-families cap, got {}",
        result.findings.len()
    );

    let serialized = serde_json::to_vec(&result.findings).unwrap();
    assert!(
        serialized.len() < 4_000_000,
        "serialized findings must fit within 4MB gRPC limit, got {} bytes",
        serialized.len()
    );

    for f in &result.findings {
        assert!(
            f.metadata.contains_key("family_id"),
            "finding must include family_id metadata"
        );
        assert!(
            f.metadata.contains_key("clone_locations"),
            "finding must include clone_locations metadata"
        );
        let locs = f.metadata.get("clone_locations").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(locs)
            .unwrap_or_else(|e| panic!("clone_locations must be valid JSON: {e}\ngot: {locs}"));
        assert!(parsed.is_array(), "clone_locations must be a JSON array");
    }
}

#[test]
fn test_duplication_json_output_consumer() {
    use chaffra_duplication::DuplicationModule;

    let module = DuplicationModule::new();
    let files = make_duplication_files();
    let mut config = HashMap::new();
    config.insert("min-tokens".to_owned(), "15".to_owned());
    let result = module.analyze(&files, &config).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Json);
    let json_str = formatter.format_result(&result, None);
    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("JSON formatter must produce valid JSON: {e}"));
    let findings = parsed.get("findings").expect("must have findings key");
    assert!(findings.is_array());
    assert!(!findings.as_array().unwrap().is_empty());

    let metrics = parsed
        .get("metrics")
        .expect("must include metrics in output");
    let counters = metrics.get("counters").expect("metrics must have counters");
    assert!(
        counters.get("raw_clone_pairs").is_some(),
        "must include raw_clone_pairs counter"
    );
    assert!(
        counters.get("clone_families").is_some(),
        "must include clone_families counter"
    );
    assert!(
        counters.get("reported_findings").is_some(),
        "must include reported_findings counter"
    );
    assert!(
        counters.get("collapsed_matches").is_some(),
        "must include collapsed_matches counter"
    );
}

#[test]
fn test_duplication_terminal_output_consumer() {
    use chaffra_duplication::DuplicationModule;

    let module = DuplicationModule::new();
    let files = make_duplication_files();
    let mut config = HashMap::new();
    config.insert("min-tokens".to_owned(), "15".to_owned());
    let result = module.analyze(&files, &config).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Terminal);
    let text = formatter.format_result(&result, None);
    assert!(
        text.contains("[W]"),
        "terminal output must contain warning severity indicator"
    );
    assert!(
        text.contains("duplicate"),
        "terminal output must contain 'duplicate' in rule description"
    );
}

#[test]
fn test_duplication_sarif_output_consumer() {
    use chaffra_duplication::DuplicationModule;

    let module = DuplicationModule::new();
    let files = make_duplication_files();
    let mut config = HashMap::new();
    config.insert("min-tokens".to_owned(), "15".to_owned());
    let result = module.analyze(&files, &config).unwrap();

    let formatter = chaffra_output::create_formatter(chaffra_output::OutputFormat::Sarif);
    let sarif_str = formatter.format_result(&result, None);
    let parsed: serde_json::Value = serde_json::from_str(&sarif_str)
        .unwrap_or_else(|e| panic!("SARIF formatter must produce valid JSON: {e}"));

    assert!(
        parsed.get("$schema").is_some(),
        "SARIF output must include $schema field"
    );
    assert_eq!(parsed["version"], "2.1.0");

    let runs = parsed["runs"].as_array().expect("must have runs array");
    assert!(!runs.is_empty());
    let results = runs[0]["results"].as_array().expect("must have results");
    assert!(
        !results.is_empty(),
        "SARIF output must contain duplication results"
    );
}

// --- Binary-spawning tests for main() dispatch coverage ---
//
// `cargo llvm-cov` propagates `LLVM_PROFILE_FILE` to subprocesses, so a
// `Command::new(env!("CARGO_BIN_EXE_chaffra"))` spawn in a test reaches the
// `tokio::main` body and the per-command match arms with the same
// instrumentation as the rest of the test binary. This is how the
// trust-boundary changed-line gate gets coverage for the `cmd_telemetry_status`
// Err-exit branch — the branch only runs from the binary entry point and
// cannot be hit from a unit test that calls the function directly (the
// `std::process::exit(1)` would tear down the test process).

#[test]
fn test_chaffra_telemetry_status_exits_nonzero_on_bad_config() {
    // F7: invalid telemetry config must produce a nonzero exit from
    // `chaffra telemetry status`, matching the behaviour of
    // `chaffra telemetry test` / `inspect`. The Err arm in
    // `cmd_telemetry_status` calls `std::process::exit(1)` after printing
    // to stderr; spawn the binary to cover that branch.
    use std::process::Command;

    let dir = tempfile::TempDir::new().unwrap();
    let bad = dir.path().join("bad.toml");
    std::fs::write(
        &bad,
        "[project]\nentry = []\n\n[modules.telemetry]\naudience = \"everyone\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_chaffra"))
        .args(["--config", bad.to_str().unwrap(), "telemetry", "status"])
        .current_dir(dir.path())
        .output()
        .expect("failed to spawn chaffra binary");

    assert!(
        !output.status.success(),
        "chaffra telemetry status must exit nonzero on invalid telemetry config; \
         status: {:?}, stdout: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid [modules.telemetry] configuration") || stderr.contains("Error:"),
        "expected typed config error on stderr, got: {stderr}"
    );
}

#[test]
fn test_chaffra_telemetry_status_succeeds_with_default_config() {
    // Companion positive test: a clean tempdir with no `.chaffra.toml` and
    // no `--config` flag must produce a successful `telemetry status` run
    // (Ok branch of `cmd_telemetry_status`). Pairs with the Err-exit test
    // above so both arms of the wrapper are reached by spawned-binary
    // coverage.
    use std::process::Command;

    let dir = tempfile::TempDir::new().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_chaffra"))
        .args(["telemetry", "status"])
        .current_dir(dir.path())
        .output()
        .expect("failed to spawn chaffra binary");

    assert!(
        output.status.success(),
        "chaffra telemetry status must succeed with default config; \
         status: {:?}, stdout: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Telemetry mode:"),
        "expected status report on stdout, got: {stdout}"
    );
}
