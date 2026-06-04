//! GitHub Actions workflow security analysis.
//!
//! Rules:
//! - `actions-dangerous-trigger`: pull_request_target / workflow_run with checkout
//! - `actions-unpinned-action`: uses a mutable tag instead of SHA
//! - `actions-excessive-permissions`: write-all or broad write
//! - `actions-script-injection`: interpolation of untrusted context in run steps

use chaffra_core::diagnostic::{Finding, Location, Severity};
use chaffra_core::error::Result;
use serde_yaml_ng::Value;
use std::collections::HashMap;

/// Analyze a GitHub Actions workflow file.
pub fn analyze(path: &str, content: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let doc: Value = serde_yaml_ng::from_str(content)
        .map_err(|e| chaffra_core::error::ChaffraError::Parse(format!("YAML parse error: {e}")))?;

    check_dangerous_triggers(path, content, &doc, findings);
    check_permissions(path, content, &doc, findings);
    check_jobs(path, content, &doc, findings);

    Ok(())
}

/// Check for dangerous workflow triggers (pull_request_target, workflow_run).
fn check_dangerous_triggers(path: &str, content: &str, doc: &Value, findings: &mut Vec<Finding>) {
    let triggers = match doc.get("on") {
        Some(v) => v,
        None => match doc {
            // serde_yaml_ng 0.9 parses bare `on:` as boolean true key
            Value::Mapping(m) => match m.get(Value::Bool(true)) {
                Some(v) => v,
                None => return,
            },
            _ => return,
        },
    };

    let has_prt = has_trigger(triggers, "pull_request_target");
    let has_wfr = has_trigger(triggers, "workflow_run");

    if !has_prt && !has_wfr {
        return;
    }

    // Check if any job checks out PR code (which makes the dangerous trigger exploitable).
    let has_checkout = content.contains("actions/checkout");
    if !has_checkout {
        return;
    }

    let trigger_name = if has_prt {
        "pull_request_target"
    } else {
        "workflow_run"
    };

    let line = find_line_number(content, trigger_name);
    findings.push(Finding {
        rule_id: "actions-dangerous-trigger".to_owned(),
        message: format!(
            "workflow uses `{trigger_name}` trigger with checkout, enabling code execution from forks"
        ),
        severity: Severity::Error,
        location: Location {
            file: path.to_owned(),
            start_line: line,
            end_line: line,
            start_column: 0,
            end_column: 0,
        },
        confidence: 0.9,
        actions: vec![],
        metadata: HashMap::new(),
    });
}

/// Check for excessive permissions.
fn check_permissions(path: &str, content: &str, doc: &Value, findings: &mut Vec<Finding>) {
    // Top-level permissions
    if let Some(perms) = doc.get("permissions") {
        check_permissions_value(path, content, perms, findings, "workflow");
    }

    // Per-job permissions
    if let Some(Value::Mapping(jobs)) = doc.get("jobs") {
        for (_job_name, job_def) in jobs {
            if let Some(perms) = job_def.get("permissions") {
                let name = match _job_name {
                    Value::String(s) => s.as_str(),
                    _ => "unknown",
                };
                check_permissions_value(path, content, perms, findings, name);
            }
        }
    }
}

fn check_permissions_value(
    path: &str,
    content: &str,
    perms: &Value,
    findings: &mut Vec<Finding>,
    scope: &str,
) {
    match perms {
        Value::String(s) if s == "write-all" => {
            let line = find_line_number(content, "write-all");
            findings.push(Finding {
                rule_id: "actions-excessive-permissions".to_owned(),
                message: format!("{scope} grants `write-all` permissions"),
                severity: Severity::Warning,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
        Value::Mapping(map) => {
            let write_count = map
                .values()
                .filter(|v| matches!(v, Value::String(s) if s == "write"))
                .count();
            if write_count >= 3 {
                let line = find_line_number(content, "permissions");
                findings.push(Finding {
                    rule_id: "actions-excessive-permissions".to_owned(),
                    message: format!(
                        "{scope} grants write to {write_count} scopes; consider narrowing"
                    ),
                    severity: Severity::Warning,
                    location: Location {
                        file: path.to_owned(),
                        start_line: line,
                        end_line: line,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.8,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
            }
        }
        _ => {}
    }
}

/// Check jobs for unpinned actions and script injection.
fn check_jobs(path: &str, content: &str, doc: &Value, findings: &mut Vec<Finding>) {
    let jobs = match doc.get("jobs") {
        Some(Value::Mapping(m)) => m,
        _ => return,
    };

    for (_job_name, job_def) in jobs {
        let steps = match job_def.get("steps") {
            Some(Value::Sequence(s)) => s,
            _ => continue,
        };

        for step in steps {
            // Check unpinned actions
            if let Some(Value::String(uses)) = step.get("uses") {
                check_unpinned_action(path, content, uses, findings);
            }

            // Check script injection in run steps
            if let Some(Value::String(run)) = step.get("run") {
                check_script_injection(path, content, run, findings);
            }
        }
    }
}

/// Check if an action reference is pinned to a SHA.
fn check_unpinned_action(path: &str, content: &str, uses: &str, findings: &mut Vec<Finding>) {
    // Skip Docker and local actions
    if uses.starts_with("docker://") || uses.starts_with("./") {
        return;
    }

    // A pinned action looks like owner/repo@<40-hex-char SHA>
    if let Some((_repo, version)) = uses.split_once('@') {
        let is_sha = version.len() == 40 && version.chars().all(|c| c.is_ascii_hexdigit());
        if !is_sha {
            let line = find_line_number(content, uses);
            findings.push(Finding {
                rule_id: "actions-unpinned-action".to_owned(),
                message: format!(
                    "action `{uses}` uses mutable ref `{version}` instead of a pinned SHA"
                ),
                severity: Severity::Warning,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    } else {
        // No @ at all
        let line = find_line_number(content, uses);
        findings.push(Finding {
            rule_id: "actions-unpinned-action".to_owned(),
            message: format!("action `{uses}` has no version pin"),
            severity: Severity::Warning,
            location: Location {
                file: path.to_owned(),
                start_line: line,
                end_line: line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        });
    }
}

/// Check for script injection via untrusted context interpolation.
fn check_script_injection(path: &str, content: &str, run: &str, findings: &mut Vec<Finding>) {
    // Dangerous context patterns that attackers control
    let dangerous_patterns = [
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.head_commit.message",
        "github.event.commits",
        "github.head_ref",
    ];

    // Look for ${{ ... }} interpolation containing dangerous contexts
    let mut search_start = 0;
    while let Some(expr_start) = run[search_start..].find("${{") {
        let abs_start = search_start + expr_start;
        if let Some(expr_end) = run[abs_start..].find("}}") {
            let expr = &run[abs_start..abs_start + expr_end + 2];
            for pattern in &dangerous_patterns {
                if expr.contains(pattern) {
                    let line = find_line_number(content, pattern);
                    findings.push(Finding {
                        rule_id: "actions-script-injection".to_owned(),
                        message: format!(
                            "untrusted input `{pattern}` interpolated in run step enables command injection"
                        ),
                        severity: Severity::Error,
                        location: Location {
                            file: path.to_owned(),
                            start_line: line,
                            end_line: line,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: 0.95,
                        actions: vec![],
                        metadata: HashMap::new(),
                    });
                    break; // One finding per expression
                }
            }
            search_start = abs_start + expr_end + 2;
        } else {
            break;
        }
    }
}

/// Check if a trigger name exists in the `on` value.
fn has_trigger(on_value: &Value, trigger: &str) -> bool {
    match on_value {
        Value::String(s) => s == trigger,
        Value::Sequence(seq) => seq
            .iter()
            .any(|v| matches!(v, Value::String(s) if s == trigger)),
        Value::Mapping(map) => map
            .keys()
            .any(|k| matches!(k, Value::String(s) if s == trigger)),
        _ => false,
    }
}

/// Find the 1-based line number of a substring in content, searching from `from` byte offset.
fn find_line_number_from(content: &str, needle: &str, from: usize) -> u32 {
    let search_start = from.min(content.len());
    if let Some(pos) = content[search_start..].find(needle) {
        content[..search_start + pos].matches('\n').count() as u32 + 1
    } else if let Some(pos) = content.find(needle) {
        // Fallback to searching from the beginning
        content[..pos].matches('\n').count() as u32 + 1
    } else {
        1
    }
}

/// Find the 1-based line number of a substring in content (searches from beginning).
fn find_line_number(content: &str, needle: &str) -> u32 {
    find_line_number_from(content, needle, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dangerous_trigger_with_checkout() {
        let yaml = r#"
name: PR Handler
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/pr.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-dangerous-trigger"),
            "should detect dangerous trigger: {findings:?}"
        );
    }

    #[test]
    fn test_dangerous_trigger_without_checkout_is_ok() {
        let yaml = r#"
name: Labeler
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: echo "no checkout here"
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/label.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "actions-dangerous-trigger"),
            "should not flag without checkout"
        );
    }

    #[test]
    fn test_unpinned_action() {
        let yaml = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v3
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        let unpinned: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "actions-unpinned-action")
            .collect();
        assert_eq!(unpinned.len(), 2, "should find 2 unpinned actions");
    }

    #[test]
    fn test_pinned_action_ok() {
        let yaml = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        let unpinned: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "actions-unpinned-action")
            .collect();
        assert!(unpinned.is_empty(), "pinned action should not be flagged");
    }

    #[test]
    fn test_local_action_ok() {
        let yaml = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ./my-local-action
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        let unpinned: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "actions-unpinned-action")
            .collect();
        assert!(unpinned.is_empty(), "local action should not be flagged");
    }

    #[test]
    fn test_excessive_permissions_write_all() {
        let yaml = r#"
name: Deploy
on: push
permissions: write-all
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/deploy.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-excessive-permissions"),
            "should detect write-all"
        );
    }

    #[test]
    fn test_excessive_permissions_many_writes() {
        let yaml = r#"
name: Deploy
on: push
permissions:
  contents: write
  packages: write
  deployments: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/deploy.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-excessive-permissions"),
            "should detect 3+ write scopes"
        );
    }

    #[test]
    fn test_minimal_permissions_ok() {
        let yaml = r#"
name: CI
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "actions-excessive-permissions"),
            "minimal permissions should not be flagged"
        );
    }

    #[test]
    fn test_script_injection() {
        let yaml = r#"
name: Issue Handler
on: issues
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/issue.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-script-injection"),
            "should detect script injection"
        );
    }

    #[test]
    fn test_safe_context_ok() {
        let yaml = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }}"
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "actions-script-injection"),
            "safe context should not be flagged"
        );
    }

    #[test]
    fn test_find_line_number() {
        let content = "line1\nline2\nline3\n";
        assert_eq!(find_line_number(content, "line1"), 1);
        assert_eq!(find_line_number(content, "line2"), 2);
        assert_eq!(find_line_number(content, "line3"), 3);
        assert_eq!(find_line_number(content, "notfound"), 1);
    }

    #[test]
    fn test_has_trigger_string() {
        let val = Value::String("push".to_owned());
        assert!(has_trigger(&val, "push"));
        assert!(!has_trigger(&val, "pull_request"));
    }

    #[test]
    fn test_has_trigger_sequence() {
        let val = Value::Sequence(vec![
            Value::String("push".to_owned()),
            Value::String("pull_request".to_owned()),
        ]);
        assert!(has_trigger(&val, "push"));
        assert!(has_trigger(&val, "pull_request"));
        assert!(!has_trigger(&val, "workflow_run"));
    }

    #[test]
    fn test_has_trigger_mapping() {
        let mut map = serde_yaml_ng::Mapping::new();
        map.insert(
            Value::String("push".to_owned()),
            Value::Mapping(serde_yaml_ng::Mapping::new()),
        );
        let val = Value::Mapping(map);
        assert!(has_trigger(&val, "push"));
        assert!(!has_trigger(&val, "pull_request"));
    }

    #[test]
    fn test_workflow_run_trigger() {
        let yaml = r#"
name: Post CI
on: workflow_run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/post.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-dangerous-trigger"),
            "should detect workflow_run with checkout"
        );
    }

    #[test]
    fn test_docker_action_ok() {
        let yaml = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine:3.18
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        let unpinned: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "actions-unpinned-action")
            .collect();
        assert!(
            unpinned.is_empty(),
            "docker:// actions should not be flagged for pinning"
        );
    }

    #[test]
    fn test_action_without_at_sign() {
        let yaml = r#"
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/some-action
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-unpinned-action"
                    && f.message.contains("no version pin")),
            "action without @ should be flagged"
        );
    }

    #[test]
    fn test_per_job_permissions() {
        let yaml = r#"
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/deploy.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "actions-excessive-permissions"),
            "should detect per-job write-all"
        );
    }

    #[test]
    fn test_multiple_injection_patterns() {
        let yaml = r#"
name: Handler
on: issues
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.issue.title }}"
          echo "${{ github.head_ref }}"
"#;
        let mut findings = Vec::new();
        analyze(".github/workflows/handler.yml", yaml, &mut findings).unwrap();
        let injection_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "actions-script-injection")
            .collect();
        assert_eq!(
            injection_findings.len(),
            2,
            "should find 2 injection patterns"
        );
    }
}
