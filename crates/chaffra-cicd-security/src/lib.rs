// TODO(#19): coverage gate unenforceable until CI tooling lands

//! CI/CD configuration security analysis module.
//!
//! Detects security misconfigurations in CI/CD pipeline definitions:
//! GitHub Actions workflows, GitLab CI pipelines, Dockerfiles, Docker Compose
//! files, and systemd service units.

pub mod compose;
pub mod detect;
pub mod dockerfile;
pub mod github_actions;
pub mod gitlab_ci;
pub mod systemd;

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, ModuleInfo, ModuleMetrics, Rule, RuleExplanation,
    Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use std::collections::HashMap;

use detect::CicdFileType;

/// All rules provided by this module.
const RULES: &[(&str, &str, &str, Severity, &str)] = &[
    // GitHub Actions
    (
        "actions-dangerous-trigger",
        "Dangerous workflow trigger",
        "Workflow uses pull_request_target or workflow_run with checkout, enabling code execution from forks",
        Severity::Error,
        "github-actions",
    ),
    (
        "actions-unpinned-action",
        "Unpinned action reference",
        "Action uses a mutable tag instead of a pinned SHA commit hash",
        Severity::Warning,
        "github-actions",
    ),
    (
        "actions-excessive-permissions",
        "Excessive workflow permissions",
        "Workflow grants write-all or broad write permissions without restriction",
        Severity::Warning,
        "github-actions",
    ),
    (
        "actions-script-injection",
        "Script injection via untrusted input",
        "Workflow interpolates user-controlled context into a run step, enabling command injection",
        Severity::Error,
        "github-actions",
    ),
    // GitLab CI
    (
        "gitlab-mutable-image",
        "Mutable container image tag",
        "Job uses :latest or an untagged image, risking supply-chain attacks",
        Severity::Warning,
        "gitlab-ci",
    ),
    (
        "gitlab-unpinned-include",
        "Unpinned remote include",
        "Pipeline includes a remote YAML without a pinned ref or hash",
        Severity::Warning,
        "gitlab-ci",
    ),
    (
        "gitlab-literal-secret",
        "Literal secret in pipeline",
        "A variable value appears to contain a hardcoded credential",
        Severity::Error,
        "gitlab-ci",
    ),
    (
        "gitlab-insecure-runner",
        "Insecure runner tag",
        "Job requests a shared or untagged runner, increasing attack surface",
        Severity::Info,
        "gitlab-ci",
    ),
    // Dockerfile
    (
        "dockerfile-run-as-root",
        "Container runs as root",
        "No USER directive sets a non-root user before the final stage entrypoint",
        Severity::Warning,
        "dockerfile",
    ),
    (
        "dockerfile-remote-add",
        "Remote ADD from URL",
        "ADD fetches content from a URL without checksum verification",
        Severity::Warning,
        "dockerfile",
    ),
    (
        "dockerfile-unpinned-base",
        "Unpinned base image",
        "FROM uses :latest or an untagged base image",
        Severity::Warning,
        "dockerfile",
    ),
    (
        "dockerfile-secrets-in-layer",
        "Secrets exposed in layer",
        "ENV, ARG, or COPY exposes a secret value that persists in the image layer",
        Severity::Error,
        "dockerfile",
    ),
    // Docker Compose
    (
        "compose-privileged",
        "Privileged container",
        "Service runs in privileged mode, granting full host access",
        Severity::Error,
        "compose",
    ),
    (
        "compose-host-network",
        "Host network mode",
        "Service uses host network mode, bypassing container network isolation",
        Severity::Warning,
        "compose",
    ),
    (
        "compose-host-mount",
        "Sensitive host path mount",
        "Service mounts a sensitive host path like /, /etc, or the Docker socket",
        Severity::Error,
        "compose",
    ),
    // systemd
    (
        "systemd-root-execution",
        "Service runs as root",
        "Service unit does not specify User= or runs explicitly as root",
        Severity::Warning,
        "systemd",
    ),
    (
        "systemd-missing-hardening",
        "Missing systemd hardening",
        "Service unit does not enable recommended sandboxing directives",
        Severity::Info,
        "systemd",
    ),
];

/// CI/CD security analysis module.
pub struct CicdSecurityModule;

impl CicdSecurityModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CicdSecurityModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisModule for CicdSecurityModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "cicd-security".to_owned(),
            name: "CI/CD Configuration Security".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["yaml".to_owned(), "dockerfile".to_owned(), "ini".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, sev, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: *sev,
                    category: (*cat).to_owned(),
                })
                .collect(),
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        _config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let mut findings = Vec::new();
        let mut files_analyzed: u64 = 0;

        for file in files {
            let file_type = detect::detect_file_type(&file.path);
            if file_type == CicdFileType::Unknown {
                continue;
            }

            files_analyzed += 1;
            let content = String::from_utf8_lossy(&file.content);

            match file_type {
                CicdFileType::GitHubActions => {
                    github_actions::analyze(&file.path, &content, &mut findings)?;
                }
                CicdFileType::GitLabCi => {
                    gitlab_ci::analyze(&file.path, &content, &mut findings)?;
                }
                CicdFileType::Dockerfile => {
                    dockerfile::analyze(&file.path, &content, &mut findings);
                }
                CicdFileType::DockerCompose => {
                    compose::analyze(&file.path, &content, &mut findings)?;
                }
                CicdFileType::Systemd => {
                    systemd::analyze(&file.path, &content, &mut findings);
                }
                CicdFileType::Unknown => {}
            }
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed,
                duration_ms: 0,
                counters: HashMap::new(),
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        for (id, name, desc, sev, _cat) in RULES {
            if *id == rule_id {
                return Ok(make_explanation(id, name, desc, *sev));
            }
        }
        Err(ChaffraError::RuleNotFound(rule_id.to_owned()))
    }

    fn fix(&self, findings: &[Finding], dry_run: bool) -> Result<Vec<FixResult>> {
        let mut results = Vec::new();
        for finding in findings {
            if finding.actions.is_empty() {
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: false,
                    edits: vec![],
                    reason: "no auto-fix available".to_owned(),
                });
            } else {
                let action = &finding.actions[0];
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: !dry_run,
                    edits: action.edits.clone(),
                    reason: if dry_run {
                        "dry run".to_owned()
                    } else {
                        "applied".to_owned()
                    },
                });
            }
        }
        Ok(results)
    }
}

fn make_explanation(id: &str, name: &str, desc: &str, sev: Severity) -> RuleExplanation {
    let (rationale, suppression, examples) = match id {
        "actions-dangerous-trigger" => (
            "pull_request_target and workflow_run triggers execute in the context of the base branch with write access to secrets. If the workflow checks out PR code, an attacker can execute arbitrary code.",
            "# chaffra:ignore actions-dangerous-trigger",
            vec!["on: pull_request_target with actions/checkout of PR HEAD".to_owned()],
        ),
        "actions-unpinned-action" => (
            "Mutable tags like @v1 or @main can be overwritten by an attacker who compromises the action repository. Pinning to a full SHA hash prevents tag-swapping attacks.",
            "# chaffra:ignore actions-unpinned-action",
            vec!["uses: actions/checkout@v4 -> uses: actions/checkout@abc123...".to_owned()],
        ),
        "actions-excessive-permissions" => (
            "Granting write-all or broad write permissions violates the principle of least privilege. An attacker exploiting any step gains those permissions.",
            "# chaffra:ignore actions-excessive-permissions",
            vec![
                "permissions: write-all".to_owned(),
                "permissions: { contents: write, packages: write }".to_owned(),
            ],
        ),
        "actions-script-injection" => (
            "Interpolating GitHub context variables like github.event.pull_request.title into run scripts allows an attacker to inject shell commands via crafted PR titles or branch names.",
            "# chaffra:ignore actions-script-injection",
            vec!["run: echo ${{ github.event.issue.title }}".to_owned()],
        ),
        "gitlab-mutable-image" => (
            "Using :latest or untagged images means the image can change without notice. A compromised registry push could inject malicious code into the build.",
            "# chaffra:ignore gitlab-mutable-image",
            vec!["image: python:latest -> image: python:3.12-slim@sha256:abc...".to_owned()],
        ),
        "gitlab-unpinned-include" => (
            "Remote includes without pinned refs can be changed by the remote owner, injecting malicious pipeline steps.",
            "# chaffra:ignore gitlab-unpinned-include",
            vec!["include: remote: 'https://example.com/ci.yml'".to_owned()],
        ),
        "gitlab-literal-secret" => (
            "Hardcoded secrets in pipeline definitions are visible to anyone with repository read access. Use CI/CD variables or a vault instead.",
            "# chaffra:ignore gitlab-literal-secret",
            vec!["variables: API_KEY: 'sk-1234567890abcdef'".to_owned()],
        ),
        "gitlab-insecure-runner" => (
            "Shared or untagged runners may be used by other projects on the same GitLab instance, increasing the risk of cross-project attacks.",
            "# chaffra:ignore gitlab-insecure-runner",
            vec!["tags: [] (no runner tags specified)".to_owned()],
        ),
        "dockerfile-run-as-root" => (
            "Running containers as root means a container breakout gives the attacker root on the host. Always use a non-root USER directive.",
            "# chaffra:ignore dockerfile-run-as-root",
            vec!["Missing USER directive before ENTRYPOINT/CMD".to_owned()],
        ),
        "dockerfile-remote-add" => (
            "ADD from a URL downloads content without integrity verification. Use COPY with a prior RUN curl/wget that checks checksums instead.",
            "# chaffra:ignore dockerfile-remote-add",
            vec!["ADD https://example.com/app.tar.gz /opt/".to_owned()],
        ),
        "dockerfile-unpinned-base" => (
            "Using :latest or untagged base images means builds are not reproducible and may pull compromised images.",
            "# chaffra:ignore dockerfile-unpinned-base",
            vec!["FROM ubuntu -> FROM ubuntu:22.04@sha256:abc...".to_owned()],
        ),
        "dockerfile-secrets-in-layer" => (
            "Secrets passed via ENV or ARG persist in image layers and can be extracted. Use build secrets (--mount=type=secret) or multi-stage builds instead.",
            "# chaffra:ignore dockerfile-secrets-in-layer",
            vec![
                "ENV API_KEY=sk-1234567890abcdef".to_owned(),
                "ARG DB_PASSWORD=hunter2".to_owned(),
            ],
        ),
        "compose-privileged" => (
            "Privileged mode disables all container isolation, giving the process full access to the host kernel. Avoid unless absolutely required.",
            "# chaffra:ignore compose-privileged",
            vec!["privileged: true".to_owned()],
        ),
        "compose-host-network" => (
            "Host network mode bypasses Docker network isolation, exposing all host ports to the container and vice versa.",
            "# chaffra:ignore compose-host-network",
            vec!["network_mode: host".to_owned()],
        ),
        "compose-host-mount" => (
            "Mounting sensitive host paths gives the container access to host system files, enabling privilege escalation.",
            "# chaffra:ignore compose-host-mount",
            vec!["volumes: ['/:/host', '/var/run/docker.sock:/var/run/docker.sock']".to_owned()],
        ),
        "systemd-root-execution" => (
            "Services running as root have unrestricted access to the system. Use User= and Group= directives to run as a dedicated service account.",
            "# chaffra:ignore systemd-root-execution",
            vec!["[Service] without User= directive".to_owned()],
        ),
        "systemd-missing-hardening" => (
            "systemd provides sandboxing directives (ProtectSystem, ProtectHome, NoNewPrivileges, PrivateTmp) that limit blast radius. Omitting them leaves the service unsandboxed.",
            "# chaffra:ignore systemd-missing-hardening",
            vec!["Missing ProtectSystem=strict, ProtectHome=yes, NoNewPrivileges=yes".to_owned()],
        ),
        _ => (
            "No additional rationale available.",
            "# chaffra:ignore <rule-id>",
            vec![],
        ),
    };

    RuleExplanation {
        rule_id: id.to_owned(),
        name: name.to_owned(),
        description: desc.to_owned(),
        rationale: rationale.to_owned(),
        default_severity: sev,
        suppression_syntax: suppression.to_owned(),
        examples,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe() {
        let module = CicdSecurityModule::new();
        let info = module.describe();
        assert_eq!(info.id, "cicd-security");
        assert_eq!(info.rules.len(), RULES.len());
        assert!(info.capabilities.contains(&"analyze".to_owned()));
        assert!(info.capabilities.contains(&"explain".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = CicdSecurityModule::default();
        let info = module.describe();
        assert_eq!(info.id, "cicd-security");
    }

    #[test]
    fn test_explain_all_rules() {
        let module = CicdSecurityModule::new();
        for (id, _, _, _, _) in RULES {
            let explanation = module.explain(id).unwrap();
            assert_eq!(explanation.rule_id, *id);
            assert!(!explanation.description.is_empty());
            assert!(!explanation.rationale.is_empty());
            assert!(!explanation.suppression_syntax.is_empty());
        }
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = CicdSecurityModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_analyze_empty() {
        let module = CicdSecurityModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.metrics.files_analyzed, 0);
    }

    #[test]
    fn test_analyze_non_cicd_files_skipped() {
        let module = CicdSecurityModule::new();
        let files = vec![FileInfo {
            path: "main.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.metrics.files_analyzed, 0);
    }

    #[test]
    fn test_fix_dry_run() {
        let module = CicdSecurityModule::new();
        let findings = vec![Finding {
            rule_id: "actions-unpinned-action".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Warning,
            location: chaffra_core::diagnostic::Location {
                file: "test.yml".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
    }

    #[test]
    fn test_fix_with_action() {
        let module = CicdSecurityModule::new();
        let findings = vec![Finding {
            rule_id: "actions-unpinned-action".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Warning,
            location: chaffra_core::diagnostic::Location {
                file: "test.yml".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![chaffra_core::diagnostic::Action {
                description: "Pin to SHA".to_owned(),
                auto_fixable: true,
                edits: vec![chaffra_core::diagnostic::TextEdit {
                    file: "test.yml".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    new_text: "pinned".to_owned(),
                }],
            }],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);
        assert_eq!(results[0].reason, "applied");
    }
}
