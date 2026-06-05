//! GitLab CI pipeline security analysis.
//!
//! Rules:
//! - `gitlab-mutable-image`: :latest or untagged container image
//! - `gitlab-unpinned-include`: remote include without pinned ref
//! - `gitlab-literal-secret`: hardcoded credential in variables
//! - `gitlab-insecure-runner`: shared or untagged runner

use chaffra_core::diagnostic::{Finding, Location, Severity};
use chaffra_core::error::Result;
use serde_yaml_ng::Value;
use std::collections::HashMap;

/// Analyze a GitLab CI pipeline file.
pub fn analyze(path: &str, content: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let doc: Value = serde_yaml_ng::from_str(content)
        .map_err(|e| chaffra_core::error::ChaffraError::Parse(format!("YAML parse error: {e}")))?;

    check_includes(path, content, &doc, findings);
    check_jobs(path, content, &doc, findings);

    Ok(())
}

/// Check for unpinned remote includes.
fn check_includes(path: &str, content: &str, doc: &Value, findings: &mut Vec<Finding>) {
    let includes = match doc.get("include") {
        Some(v) => v,
        None => return,
    };

    let include_list = match includes {
        Value::Sequence(seq) => seq.clone(),
        other => vec![other.clone()],
    };

    for inc in &include_list {
        match inc {
            Value::String(s) if is_remote_url(s) => {
                let line = find_line_number(content, s);
                findings.push(make_unpinned_include(path, s, line));
            }
            Value::Mapping(map) => {
                if let Some(Value::String(remote)) = map.get(Value::String("remote".to_owned())) {
                    if !has_pinned_ref(remote) {
                        let line = find_line_number(content, remote);
                        findings.push(make_unpinned_include(path, remote, line));
                    }
                }
            }
            _ => {}
        }
    }
}

/// Check jobs for mutable images, literal secrets, and insecure runners.
fn check_jobs(path: &str, content: &str, doc: &Value, findings: &mut Vec<Finding>) {
    let mapping = match doc {
        Value::Mapping(m) => m,
        _ => return,
    };

    // Check default image
    if let Some(image_val) = mapping.get(Value::String("image".to_owned())) {
        check_image(path, content, image_val, findings, "default");
    }

    // Check global variables
    if let Some(vars) = mapping.get(Value::String("variables".to_owned())) {
        check_variables(path, content, vars, findings, "global");
    }

    for (key, value) in mapping {
        let job_name = match key {
            Value::String(s) => s.clone(),
            _ => continue,
        };

        // Skip GitLab CI keywords that are not jobs
        if is_gitlab_keyword(&job_name) {
            continue;
        }

        let job_def = match value {
            Value::Mapping(_) => value,
            _ => continue,
        };

        // Check image
        if let Some(image_val) = job_def.get("image") {
            check_image(path, content, image_val, findings, &job_name);
        }

        // Check variables for secrets
        if let Some(vars) = job_def.get("variables") {
            check_variables(path, content, vars, findings, &job_name);
        }

        // Check runner tags
        check_runner_tags(path, content, job_def, findings, &job_name);
    }
}

/// Check if an image reference is mutable.
fn check_image(
    path: &str,
    content: &str,
    image_val: &Value,
    findings: &mut Vec<Finding>,
    scope: &str,
) {
    let image_str = match image_val {
        Value::String(s) => s.clone(),
        Value::Mapping(m) => match m.get(Value::String("name".to_owned())) {
            Some(Value::String(s)) => s.clone(),
            _ => return,
        },
        _ => return,
    };

    if is_mutable_image(&image_str) {
        let line = find_line_number(content, &image_str);
        findings.push(Finding {
            rule_id: "gitlab-mutable-image".to_owned(),
            message: format!("{scope} uses mutable image `{image_str}`"),
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

/// Check variables for literal secrets.
fn check_variables(
    path: &str,
    content: &str,
    vars: &Value,
    findings: &mut Vec<Finding>,
    scope: &str,
) {
    let mapping = match vars {
        Value::Mapping(m) => m,
        _ => return,
    };

    for (key, value) in mapping {
        let var_name = match key {
            Value::String(s) => s.clone(),
            _ => continue,
        };
        let var_value = match value {
            Value::String(s) => s.clone(),
            _ => continue,
        };

        if looks_like_secret(&var_name, &var_value) {
            let line = find_line_number(content, &var_value);
            findings.push(Finding {
                rule_id: "gitlab-literal-secret".to_owned(),
                message: format!(
                    "{scope} variable `{var_name}` appears to contain a hardcoded secret"
                ),
                severity: Severity::Error,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.85,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    }
}

/// Check runner tags.
fn check_runner_tags(
    path: &str,
    content: &str,
    job_def: &Value,
    findings: &mut Vec<Finding>,
    job_name: &str,
) {
    let tags = job_def.get("tags");
    match tags {
        None => {
            // No tags = shared runner
            let line = find_line_number(content, job_name);
            findings.push(Finding {
                rule_id: "gitlab-insecure-runner".to_owned(),
                message: format!("job `{job_name}` has no runner tags, will use shared runners"),
                severity: Severity::Info,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.7,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
        Some(Value::Sequence(seq)) if seq.is_empty() => {
            let line = find_line_number(content, "tags");
            findings.push(Finding {
                rule_id: "gitlab-insecure-runner".to_owned(),
                message: format!("job `{job_name}` has empty runner tags"),
                severity: Severity::Info,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.7,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
        _ => {} // Has specific tags, OK
    }
}

fn make_unpinned_include(path: &str, url: &str, line: u32) -> Finding {
    Finding {
        rule_id: "gitlab-unpinned-include".to_owned(),
        message: format!("remote include `{url}` is not pinned to a specific ref"),
        severity: Severity::Warning,
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
    }
}

fn is_remote_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn has_pinned_ref(url: &str) -> bool {
    // Check for @sha, @v1.2.3, or ?ref= patterns
    url.contains("@sha256:") || url.contains("?ref=")
}

fn is_mutable_image(image: &str) -> bool {
    // Mutable if :latest or no tag at all
    if image.ends_with(":latest") {
        return true;
    }
    // No tag: check if there's no colon after the last slash (registry path)
    // e.g. "python" or "registry.example.com/app" have no tag
    let after_registry = image.rsplit('/').next().unwrap_or(image);
    !after_registry.contains(':')
}

fn is_gitlab_keyword(name: &str) -> bool {
    // Dot-prefixed keys are hidden YAML anchor/template definitions, not jobs
    if name.starts_with('.') {
        return true;
    }
    matches!(
        name,
        "image"
            | "services"
            | "stages"
            | "variables"
            | "include"
            | "default"
            | "workflow"
            | "before_script"
            | "after_script"
            | "cache"
            | "pages"
            | "trigger"
            | "rules"
            | "artifacts"
            | "needs"
            | "extends"
            | "retry"
            | "interruptible"
            | "timeout"
            | "resource_group"
            | "environment"
            | "release"
            | "secrets"
            | "id_tokens"
            | "when"
            | "allow_failure"
            | "parallel"
            | "dependencies"
    )
}

/// Heuristic to detect likely secrets in variable values.
fn looks_like_secret(name: &str, value: &str) -> bool {
    let name_lower = name.to_lowercase();
    let secret_name_patterns = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "auth",
    ];

    let has_secret_name = secret_name_patterns.iter().any(|p| name_lower.contains(p));

    if !has_secret_name {
        return false;
    }

    // Skip CI variable references
    if value.starts_with('$') || value.starts_with("${") {
        return false;
    }

    // Must have some minimum length to be a plausible secret
    value.len() >= 8
}

/// Find the 1-based line number of a substring in content, searching from `from` byte offset.
fn find_line_number_from(content: &str, needle: &str, from: usize) -> u32 {
    let search_start = from.min(content.len());
    if let Some(pos) = content[search_start..].find(needle) {
        content[..search_start + pos].matches('\n').count() as u32 + 1
    } else if let Some(pos) = content.find(needle) {
        content[..pos].matches('\n').count() as u32 + 1
    } else {
        1
    }
}

fn find_line_number(content: &str, needle: &str) -> u32 {
    find_line_number_from(content, needle, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mutable_image_latest() {
        let yaml = r#"
image: python:latest

test:
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "gitlab-mutable-image"),
            "should detect :latest image: {findings:?}"
        );
    }

    #[test]
    fn test_mutable_image_no_tag() {
        let yaml = r#"
stages:
  - test

test:
  image: python
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        let mutable: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "gitlab-mutable-image")
            .collect();
        assert!(!mutable.is_empty(), "should detect untagged image");
    }

    #[test]
    fn test_pinned_image_ok() {
        let yaml = r#"
test:
  image: python:3.12-slim
  tags:
    - docker
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().all(|f| f.rule_id != "gitlab-mutable-image"),
            "pinned image should not be flagged"
        );
    }

    #[test]
    fn test_unpinned_remote_include() {
        let yaml = r#"
include:
  - remote: 'https://example.com/ci-templates/base.yml'

test:
  tags:
    - docker
  script: make test
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "gitlab-unpinned-include"),
            "should detect unpinned remote include: {findings:?}"
        );
    }

    #[test]
    fn test_pinned_include_ok() {
        let yaml = r#"
include:
  - remote: 'https://example.com/ci.yml?ref=abc123'

test:
  tags:
    - docker
  script: make test
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "gitlab-unpinned-include"),
            "pinned include should not be flagged"
        );
    }

    #[test]
    fn test_literal_secret() {
        let yaml = r#"
variables:
  API_KEY: "sk-1234567890abcdef1234567890abcdef"

test:
  tags:
    - docker
  script: "curl -H 'Auth: $API_KEY'"
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "gitlab-literal-secret"),
            "should detect literal secret: {findings:?}"
        );
    }

    #[test]
    fn test_variable_reference_ok() {
        let yaml = r#"
variables:
  API_KEY: $CI_SECRET_KEY

test:
  tags:
    - docker
  script: "curl -H 'Auth: $API_KEY'"
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "gitlab-literal-secret"),
            "variable reference should not be flagged"
        );
    }

    #[test]
    fn test_insecure_runner_no_tags() {
        let yaml = r#"
test:
  image: python:3.12
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "gitlab-insecure-runner"),
            "should detect missing runner tags: {findings:?}"
        );
    }

    #[test]
    fn test_runner_with_tags_ok() {
        let yaml = r#"
test:
  image: python:3.12
  tags:
    - docker
    - private
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "gitlab-insecure-runner"),
            "tagged runner should not be flagged"
        );
    }

    #[test]
    fn test_is_mutable_image() {
        assert!(is_mutable_image("python:latest"));
        assert!(is_mutable_image("python"));
        assert!(is_mutable_image("registry.example.com/app"));
        assert!(!is_mutable_image("python:3.12-slim"));
        assert!(!is_mutable_image("python:3.12@sha256:abc123"));
    }

    #[test]
    fn test_is_remote_url() {
        assert!(is_remote_url("https://example.com/ci.yml"));
        assert!(is_remote_url("http://example.com/ci.yml"));
        assert!(!is_remote_url("local/ci.yml"));
    }

    #[test]
    fn test_has_pinned_ref() {
        assert!(has_pinned_ref("https://example.com/ci.yml?ref=abc123"));
        assert!(has_pinned_ref("img@sha256:abc123"));
        assert!(!has_pinned_ref("https://example.com/ci.yml"));
    }

    #[test]
    fn test_is_gitlab_keyword() {
        assert!(is_gitlab_keyword("image"));
        assert!(is_gitlab_keyword("stages"));
        assert!(is_gitlab_keyword("variables"));
        assert!(is_gitlab_keyword("trigger"));
        assert!(is_gitlab_keyword("rules"));
        assert!(is_gitlab_keyword("artifacts"));
        assert!(is_gitlab_keyword("needs"));
        assert!(is_gitlab_keyword("extends"));
        assert!(is_gitlab_keyword("retry"));
        assert!(is_gitlab_keyword("interruptible"));
        assert!(is_gitlab_keyword("timeout"));
        assert!(is_gitlab_keyword("resource_group"));
        assert!(is_gitlab_keyword("environment"));
        assert!(is_gitlab_keyword("release"));
        assert!(is_gitlab_keyword("secrets"));
        assert!(is_gitlab_keyword("id_tokens"));
        assert!(is_gitlab_keyword("when"));
        assert!(is_gitlab_keyword("allow_failure"));
        assert!(is_gitlab_keyword("parallel"));
        assert!(is_gitlab_keyword("dependencies"));
        // Dot-prefixed hidden keys (YAML anchors/templates)
        assert!(is_gitlab_keyword(".template-base"));
        assert!(is_gitlab_keyword(".shared-config"));
        // Actual job names
        assert!(!is_gitlab_keyword("my-job"));
        assert!(!is_gitlab_keyword("deploy"));
    }

    #[test]
    fn test_looks_like_secret() {
        assert!(looks_like_secret("API_KEY", "sk-1234567890abcdef"));
        assert!(looks_like_secret("DB_PASSWORD", "hunter2hunter2"));
        assert!(!looks_like_secret("API_KEY", "$SECRET"));
        assert!(!looks_like_secret("API_KEY", "short"));
        assert!(!looks_like_secret("APP_NAME", "my-application"));
    }

    #[test]
    fn test_image_with_name_field() {
        let yaml = r#"
test:
  image:
    name: python:latest
  tags:
    - docker
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "gitlab-mutable-image"),
            "should detect :latest in image.name: {findings:?}"
        );
    }

    #[test]
    fn test_string_include() {
        let yaml = r#"
include: 'https://example.com/templates/ci.yml'

test:
  tags:
    - docker
  script: make test
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "gitlab-unpinned-include"),
            "should detect unpinned string include"
        );
    }

    #[test]
    fn test_empty_tags() {
        let yaml = r#"
test:
  image: python:3.12
  tags: []
  script: pytest
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "gitlab-insecure-runner"),
            "empty tags should be flagged"
        );
    }

    #[test]
    fn test_job_level_variables_secret() {
        let yaml = r#"
deploy:
  tags:
    - docker
  variables:
    SECRET_TOKEN: "abcdef1234567890"
  script: deploy.sh
"#;
        let mut findings = Vec::new();
        analyze(".gitlab-ci.yml", yaml, &mut findings).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "gitlab-literal-secret"),
            "should detect secret in job variables"
        );
    }
}
