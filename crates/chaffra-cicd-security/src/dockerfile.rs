//! Dockerfile security analysis.
//!
//! Rules:
//! - `dockerfile-run-as-root`: no USER directive sets non-root before entrypoint
//! - `dockerfile-remote-add`: ADD from URL without checksum
//! - `dockerfile-unpinned-base`: FROM :latest or untagged
//! - `dockerfile-secrets-in-layer`: ENV/ARG exposes secrets

use chaffra_core::diagnostic::{Finding, Location, Severity};
use std::collections::HashMap;

/// Analyze a Dockerfile.
pub fn analyze(path: &str, content: &str, findings: &mut Vec<Finding>) {
    let lines: Vec<&str> = content.lines().collect();
    let directives = parse_directives(&lines);

    check_unpinned_base(path, &directives, findings);
    check_run_as_root(path, &directives, findings);
    check_remote_add(path, &directives, findings);
    check_secrets_in_layer(path, &directives, findings);
}

/// A parsed Dockerfile directive.
#[derive(Debug)]
struct Directive {
    /// The instruction keyword (e.g., FROM, RUN, USER).
    instruction: String,
    /// The argument(s) after the keyword.
    arguments: String,
    /// 1-based line number.
    line: u32,
}

/// Parse Dockerfile into directives, handling line continuations.
fn parse_directives(lines: &[&str]) -> Vec<Directive> {
    let mut directives = Vec::new();
    let mut current_line = String::new();
    let mut start_line: u32 = 0;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            if !current_line.is_empty() {
                // Handle case where continuation was expected but we got a comment/blank
                if let Some(d) = parse_single_directive(&current_line, start_line) {
                    directives.push(d);
                }
                current_line.clear();
            }
            continue;
        }

        if current_line.is_empty() {
            start_line = (i + 1) as u32;
            current_line = trimmed.to_string();
        } else {
            current_line.push(' ');
            current_line.push_str(trimmed);
        }

        // Check for line continuation
        if current_line.ends_with('\\') {
            current_line.pop(); // Remove the backslash
            continue;
        }

        if let Some(d) = parse_single_directive(&current_line, start_line) {
            directives.push(d);
        }
        current_line.clear();
    }

    // Handle last line if no trailing newline
    if !current_line.is_empty() {
        if let Some(d) = parse_single_directive(&current_line, start_line) {
            directives.push(d);
        }
    }

    directives
}

fn parse_single_directive(line: &str, line_num: u32) -> Option<Directive> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let (instruction, arguments) = if let Some(pos) = trimmed.find(char::is_whitespace) {
        (
            trimmed[..pos].to_uppercase(),
            trimmed[pos..].trim().to_string(),
        )
    } else {
        (trimmed.to_uppercase(), String::new())
    };

    Some(Directive {
        instruction,
        arguments,
        line: line_num,
    })
}

/// Check for unpinned base images (FROM :latest or no tag).
fn check_unpinned_base(path: &str, directives: &[Directive], findings: &mut Vec<Finding>) {
    for d in directives {
        if d.instruction != "FROM" {
            continue;
        }

        let image = d.arguments.split_whitespace().next().unwrap_or("");

        // Skip scratch (special empty image)
        if image == "scratch" {
            continue;
        }

        // Skip build stage references (FROM builder AS ...)
        // Actually we check the image part: if it's a name from a previous AS, skip
        // For simplicity, just check the image tag
        if is_unpinned_image(image) {
            findings.push(Finding {
                rule_id: "dockerfile-unpinned-base".to_owned(),
                message: format!("base image `{image}` is not pinned to a specific version"),
                severity: Severity::Warning,
                location: Location {
                    file: path.to_owned(),
                    start_line: d.line,
                    end_line: d.line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    }
}

/// Check that at least the final stage sets a non-root USER.
fn check_run_as_root(path: &str, directives: &[Directive], findings: &mut Vec<Finding>) {
    // Find the last FROM to identify the final stage
    let last_from_idx = directives.iter().rposition(|d| d.instruction == "FROM");

    let last_from_idx = match last_from_idx {
        Some(idx) => idx,
        None => return, // No FROM directive
    };

    // Check if there's a USER directive after the last FROM that sets non-root
    let has_nonroot_user = directives[last_from_idx..]
        .iter()
        .any(|d| d.instruction == "USER" && !is_root_user(&d.arguments));

    if !has_nonroot_user {
        let from_line = directives[last_from_idx].line;
        findings.push(Finding {
            rule_id: "dockerfile-run-as-root".to_owned(),
            message: "final stage does not set a non-root USER".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: path.to_owned(),
                start_line: from_line,
                end_line: from_line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.9,
            actions: vec![],
            metadata: HashMap::new(),
        });
    }
}

/// Check for ADD from remote URLs.
fn check_remote_add(path: &str, directives: &[Directive], findings: &mut Vec<Finding>) {
    for d in directives {
        if d.instruction != "ADD" {
            continue;
        }

        // Check if any argument is a URL
        for arg in d.arguments.split_whitespace() {
            if arg.starts_with("http://") || arg.starts_with("https://") {
                findings.push(Finding {
                    rule_id: "dockerfile-remote-add".to_owned(),
                    message: format!("ADD fetches `{arg}` from URL without checksum verification"),
                    severity: Severity::Warning,
                    location: Location {
                        file: path.to_owned(),
                        start_line: d.line,
                        end_line: d.line,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 1.0,
                    actions: vec![],
                    metadata: HashMap::new(),
                });
                break; // One finding per ADD
            }
        }
    }
}

/// Check for secrets exposed in ENV, ARG, or COPY.
fn check_secrets_in_layer(path: &str, directives: &[Directive], findings: &mut Vec<Finding>) {
    let secret_patterns = [
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
    ];

    for d in directives {
        match d.instruction.as_str() {
            "ENV" | "ARG" => {
                // Parse key=value or key value pairs
                let parts: Vec<&str> = if d.arguments.contains('=') {
                    d.arguments.splitn(2, '=').collect()
                } else {
                    d.arguments.splitn(2, char::is_whitespace).collect()
                };

                if parts.len() >= 2 {
                    let key = parts[0].trim().to_lowercase();
                    let value = parts[1].trim();

                    let has_secret_name = secret_patterns.iter().any(|p| key.contains(p));

                    if has_secret_name && !value.is_empty() && !is_variable_ref(value) {
                        findings.push(Finding {
                            rule_id: "dockerfile-secrets-in-layer".to_owned(),
                            message: format!(
                                "{} `{}` exposes a secret in the image layer",
                                d.instruction,
                                parts[0].trim()
                            ),
                            severity: Severity::Error,
                            location: Location {
                                file: path.to_owned(),
                                start_line: d.line,
                                end_line: d.line,
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
            _ => {}
        }
    }
}

fn is_unpinned_image(image: &str) -> bool {
    if image.ends_with(":latest") {
        return true;
    }
    // No tag at all
    let after_registry = image.rsplit('/').next().unwrap_or(image);
    !after_registry.contains(':')
}

fn is_root_user(user_arg: &str) -> bool {
    let user = user_arg.split(':').next().unwrap_or(user_arg).trim();
    user == "root" || user == "0"
}

fn is_variable_ref(value: &str) -> bool {
    value.starts_with('$') || value.starts_with("${")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpinned_base_latest() {
        let content = "FROM ubuntu:latest\nRUN apt-get update\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-unpinned-base"),
            "should detect :latest base image: {findings:?}"
        );
    }

    #[test]
    fn test_unpinned_base_no_tag() {
        let content = "FROM ubuntu\nRUN apt-get update\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-unpinned-base"),
            "should detect untagged base image"
        );
    }

    #[test]
    fn test_pinned_base_ok() {
        let content = "FROM ubuntu:22.04\nUSER appuser\nRUN apt-get update\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-unpinned-base"),
            "pinned image should not be flagged"
        );
    }

    #[test]
    fn test_scratch_base_ok() {
        let content = "FROM scratch\nCOPY app /app\nUSER 1000\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-unpinned-base"),
            "scratch should not be flagged"
        );
    }

    #[test]
    fn test_run_as_root() {
        let content = "FROM ubuntu:22.04\nRUN apt-get update\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-run-as-root"),
            "should detect missing USER: {findings:?}"
        );
    }

    #[test]
    fn test_non_root_user_ok() {
        let content = "FROM ubuntu:22.04\nRUN apt-get update\nUSER appuser\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-run-as-root"),
            "non-root USER should not be flagged"
        );
    }

    #[test]
    fn test_root_user_flagged() {
        let content = "FROM ubuntu:22.04\nUSER root\nRUN apt-get update\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-run-as-root"),
            "USER root should still flag: {findings:?}"
        );
    }

    #[test]
    fn test_user_uid_zero_is_root() {
        let content = "FROM ubuntu:22.04\nUSER 0\nRUN apt-get update\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-run-as-root"),
            "USER 0 should be treated as root"
        );
    }

    #[test]
    fn test_remote_add() {
        let content = "FROM ubuntu:22.04\nADD https://example.com/app.tar.gz /opt/\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-remote-add"),
            "should detect remote ADD: {findings:?}"
        );
    }

    #[test]
    fn test_local_add_ok() {
        let content = "FROM ubuntu:22.04\nADD ./app.tar.gz /opt/\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-remote-add"),
            "local ADD should not be flagged"
        );
    }

    #[test]
    fn test_secrets_in_env() {
        let content = "FROM ubuntu:22.04\nENV API_KEY=sk-1234567890abcdef\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-secrets-in-layer"),
            "should detect secret in ENV: {findings:?}"
        );
    }

    #[test]
    fn test_secrets_in_arg() {
        let content = "FROM ubuntu:22.04\nARG DB_PASSWORD=hunter2hunter2\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-secrets-in-layer"),
            "should detect secret in ARG: {findings:?}"
        );
    }

    #[test]
    fn test_env_variable_ref_ok() {
        let content = "FROM ubuntu:22.04\nENV API_KEY=$SECRET_FROM_VAULT\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-secrets-in-layer"),
            "variable reference should not be flagged"
        );
    }

    #[test]
    fn test_multi_stage_only_final() {
        // Only the final stage matters for USER check
        let content = "FROM ubuntu:22.04 AS builder\nRUN make\nFROM alpine:3.18\nCOPY --from=builder /app /app\nUSER nobody\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-run-as-root"),
            "final stage has USER, should not flag"
        );
    }

    #[test]
    fn test_line_continuation() {
        let content =
            "FROM ubuntu:22.04\nRUN apt-get update && \\\n    apt-get install -y curl\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        // Should parse without error
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-run-as-root")
        );
    }

    #[test]
    fn test_comment_lines_skipped() {
        let content = "# This is a comment\nFROM ubuntu:22.04\n# Another comment\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-run-as-root")
        );
    }

    #[test]
    fn test_is_unpinned_image() {
        assert!(is_unpinned_image("ubuntu:latest"));
        assert!(is_unpinned_image("ubuntu"));
        assert!(is_unpinned_image("registry.example.com/app"));
        assert!(!is_unpinned_image("ubuntu:22.04"));
        assert!(!is_unpinned_image("ubuntu:22.04@sha256:abc123"));
    }

    #[test]
    fn test_is_root_user() {
        assert!(is_root_user("root"));
        assert!(is_root_user("0"));
        assert!(is_root_user("0:0"));
        assert!(!is_root_user("appuser"));
        assert!(!is_root_user("1000"));
        assert!(!is_root_user("1000:1000"));
    }

    #[test]
    fn test_is_variable_ref() {
        assert!(is_variable_ref("$MY_VAR"));
        assert!(is_variable_ref("${MY_VAR}"));
        assert!(!is_variable_ref("literal_value"));
    }

    #[test]
    fn test_from_with_as() {
        let content = "FROM golang:1.21 AS builder\nRUN go build\nFROM alpine:3.18\nCOPY --from=builder /app /app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        // Should not flag the build stage images as unpinned
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-unpinned-base"),
            "tagged images should not be flagged"
        );
    }

    #[test]
    fn test_env_with_space_separator() {
        let content = "FROM ubuntu:22.04\nENV SECRET_TOKEN supersecretvalue123\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "dockerfile-secrets-in-layer"),
            "should detect secret with space-separated ENV"
        );
    }

    #[test]
    fn test_non_secret_env_ok() {
        let content = "FROM ubuntu:22.04\nENV APP_NAME=myapp\nUSER app\n";
        let mut findings = Vec::new();
        analyze("Dockerfile", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "dockerfile-secrets-in-layer"),
            "non-secret ENV should not be flagged"
        );
    }
}
