//! Security analysis module -- SAST, secret scanning, and dependency CVE detection.
//!
//! This module provides three security capabilities:
//!
//! - **SAST (Static Application Security Testing)**: Intraprocedural taint analysis
//!   that tracks data flow from user-controlled sources to dangerous sinks.
//! - **Secret scanning**: Pattern-based detection of hardcoded credentials, API keys,
//!   and high-entropy strings that may be secrets.
//! - **Dependency CVE scanning**: Offline vulnerability checking against known-bad
//!   version ranges in dependency manifests.

pub mod deps;
pub mod sast;
pub mod secrets;

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, ModuleInfo, ModuleMetrics, Rule, RuleExplanation,
    Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use std::collections::HashMap;

/// Security analysis module.
pub struct SecurityModule;

impl SecurityModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SecurityModule {
    fn default() -> Self {
        Self::new()
    }
}

/// All rules provided by this module.
const RULES: &[(&str, &str, &str, Severity, &str)] = &[
    (
        "sql-injection",
        "SQL injection",
        "Tainted data flows into a SQL query without parameterization",
        Severity::Error,
        "sast",
    ),
    (
        "command-injection",
        "Command injection",
        "Tainted data flows into an OS command execution call",
        Severity::Error,
        "sast",
    ),
    (
        "xss",
        "Cross-site scripting (XSS)",
        "Tainted data flows into HTML output without escaping",
        Severity::Error,
        "sast",
    ),
    (
        "ssrf",
        "Server-side request forgery (SSRF)",
        "Tainted data controls the URL of an outbound HTTP request",
        Severity::Error,
        "sast",
    ),
    (
        "path-traversal",
        "Path traversal",
        "Tainted data flows into a file path without validation",
        Severity::Error,
        "sast",
    ),
    (
        "unsafe-deserialization",
        "Unsafe deserialization",
        "Untrusted data is deserialized using an unsafe method",
        Severity::Error,
        "sast",
    ),
    (
        "hardcoded-secret",
        "Hardcoded secret",
        "API key, password, or credential embedded in source code",
        Severity::Error,
        "secrets",
    ),
    (
        "high-entropy-string",
        "High-entropy string",
        "String with unusually high Shannon entropy that may be a secret",
        Severity::Warning,
        "secrets",
    ),
    (
        "vulnerable-dependency",
        "Vulnerable dependency",
        "Dependency has a known CVE or security advisory in its version range",
        Severity::Warning,
        "deps",
    ),
];

impl AnalysisModule for SecurityModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "security".to_owned(),
            name: "Security Analysis".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, severity, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: *severity,
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
        let mut findings: Vec<Finding> = Vec::new();
        let mut files_analyzed: u64 = 0;

        for file in files {
            // SAST analysis (Go + Python source files).
            let sast_findings = sast::analyze_file(file);
            if !sast_findings.is_empty() {
                files_analyzed += 1;
                findings.extend(sast_findings);
            }

            // Secret scanning (all text files except tests).
            let secret_findings = secrets::scan_file(file);
            if !secret_findings.is_empty() {
                if sast_findings_count_for_file(&findings, &file.path) == 0 {
                    files_analyzed += 1;
                }
                findings.extend(secret_findings);
            }

            // Dependency manifest scanning.
            let dep_findings = deps::scan_manifest(file);
            if !dep_findings.is_empty() {
                files_analyzed += 1;
                findings.extend(dep_findings);
            }
        }

        // Count by category for metrics.
        let sast_count = findings.iter().filter(|f| is_sast_rule(&f.rule_id)).count() as u64;
        let secret_count = findings
            .iter()
            .filter(|f| is_secret_rule(&f.rule_id))
            .count() as u64;
        let dep_count = findings
            .iter()
            .filter(|f| f.rule_id == "vulnerable-dependency")
            .count() as u64;

        let mut counters = HashMap::new();
        counters.insert("sast_findings".to_owned(), sast_count);
        counters.insert("secret_findings".to_owned(), secret_count);
        counters.insert("dependency_findings".to_owned(), dep_count);

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed,
                duration_ms: 0,
                counters,
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "sql-injection" => Ok(RuleExplanation {
                rule_id: "sql-injection".to_owned(),
                name: "SQL injection".to_owned(),
                description: "Detects tainted data flowing from user input into SQL queries without proper parameterization or escaping.".to_owned(),
                rationale: "SQL injection is a critical vulnerability that allows attackers to execute arbitrary SQL commands, potentially reading, modifying, or deleting data.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore sql-injection".to_owned(),
                examples: vec![
                    "db.Query(\"SELECT * FROM users WHERE id = '\" + userInput + \"'\")".to_owned(),
                    "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")".to_owned(),
                ],
            }),
            "command-injection" => Ok(RuleExplanation {
                rule_id: "command-injection".to_owned(),
                name: "Command injection".to_owned(),
                description: "Detects tainted data flowing from user input into OS command execution calls.".to_owned(),
                rationale: "Command injection allows attackers to execute arbitrary system commands, leading to complete system compromise.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore command-injection".to_owned(),
                examples: vec![
                    "exec.Command(userInput)".to_owned(),
                    "os.system(request.args.get('cmd'))".to_owned(),
                ],
            }),
            "xss" => Ok(RuleExplanation {
                rule_id: "xss".to_owned(),
                name: "Cross-site scripting (XSS)".to_owned(),
                description: "Detects tainted data flowing into HTML output without proper escaping.".to_owned(),
                rationale: "XSS allows attackers to inject malicious scripts into web pages viewed by other users, enabling session hijacking and data theft.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore xss".to_owned(),
                examples: vec![
                    "fmt.Fprintf(w, \"<h1>Hello %s</h1>\", userInput)".to_owned(),
                    "render_template_string(\"<p>\" + user_name + \"</p>\")".to_owned(),
                ],
            }),
            "ssrf" => Ok(RuleExplanation {
                rule_id: "ssrf".to_owned(),
                name: "Server-side request forgery (SSRF)".to_owned(),
                description: "Detects tainted data controlling the URL of outbound HTTP requests.".to_owned(),
                rationale: "SSRF allows attackers to make the server perform requests to internal resources, bypassing firewalls and accessing sensitive services.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore ssrf".to_owned(),
                examples: vec![
                    "http.Get(r.FormValue(\"url\"))".to_owned(),
                    "requests.get(request.args.get('url'))".to_owned(),
                ],
            }),
            "path-traversal" => Ok(RuleExplanation {
                rule_id: "path-traversal".to_owned(),
                name: "Path traversal".to_owned(),
                description: "Detects tainted data flowing into file system path operations without validation.".to_owned(),
                rationale: "Path traversal allows attackers to read or write arbitrary files on the server by manipulating path components.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore path-traversal".to_owned(),
                examples: vec![
                    "os.Open(r.FormValue(\"file\"))".to_owned(),
                    "open(request.args.get('path'))".to_owned(),
                ],
            }),
            "unsafe-deserialization" => Ok(RuleExplanation {
                rule_id: "unsafe-deserialization".to_owned(),
                name: "Unsafe deserialization".to_owned(),
                description: "Detects deserialization of untrusted data using methods that can execute arbitrary code.".to_owned(),
                rationale: "Unsafe deserialization can lead to remote code execution when an attacker controls the serialized input.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore unsafe-deserialization".to_owned(),
                examples: vec![
                    "pickle.loads(request.data)".to_owned(),
                    "yaml.load(user_input)".to_owned(),
                ],
            }),
            "hardcoded-secret" => Ok(RuleExplanation {
                rule_id: "hardcoded-secret".to_owned(),
                name: "Hardcoded secret".to_owned(),
                description: "Detects API keys, passwords, tokens, and other credentials embedded directly in source code.".to_owned(),
                rationale: "Hardcoded secrets are easily extracted from source code, version control history, or compiled binaries, leading to unauthorized access.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore hardcoded-secret".to_owned(),
                examples: vec![
                    "const API_KEY = \"AKIAIOSFODNN7EXAMPLE\"".to_owned(),
                    "password = \"s3cret\"".to_owned(),
                ],
            }),
            "high-entropy-string" => Ok(RuleExplanation {
                rule_id: "high-entropy-string".to_owned(),
                name: "High-entropy string".to_owned(),
                description: "Flags strings with unusually high Shannon entropy that may be secrets, tokens, or keys not matched by known patterns.".to_owned(),
                rationale: "High-entropy strings in source code are often secrets that should be externalized to environment variables or a secrets manager.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore high-entropy-string".to_owned(),
                examples: vec![
                    "var token = \"a8Kx3mPq9wNzB7yC2eRt5vG4hJ6kL0sD\"".to_owned(),
                ],
            }),
            "vulnerable-dependency" => Ok(RuleExplanation {
                rule_id: "vulnerable-dependency".to_owned(),
                name: "Vulnerable dependency".to_owned(),
                description: "Detects dependencies with known CVEs or security advisories based on version ranges in manifest files.".to_owned(),
                rationale: "Vulnerable dependencies can be exploited by attackers to compromise applications, even if the application code itself is secure.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore vulnerable-dependency".to_owned(),
                examples: vec![
                    "flask==2.3.0 (CVE-2023-30861)".to_owned(),
                    "golang.org/x/net v0.20.0 (CVE-2024-24790)".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Security findings generally cannot be auto-fixed safely.
        Ok(findings
            .iter()
            .map(|f| FixResult {
                rule_id: f.rule_id.clone(),
                applied: false,
                edits: vec![],
                reason: "security findings require manual review and remediation".to_owned(),
            })
            .collect())
    }
}

/// Check if a rule ID is a SAST rule.
fn is_sast_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "sql-injection"
            | "command-injection"
            | "xss"
            | "ssrf"
            | "path-traversal"
            | "unsafe-deserialization"
    )
}

/// Check if a rule ID is a secret scanning rule.
fn is_secret_rule(rule_id: &str) -> bool {
    matches!(rule_id, "hardcoded-secret" | "high-entropy-string")
}

/// Count SAST findings for a specific file (to avoid double-counting files).
fn sast_findings_count_for_file(findings: &[Finding], file_path: &str) -> usize {
    findings
        .iter()
        .filter(|f| f.location.file == file_path && is_sast_rule(&f.rule_id))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file(path: &str, content: &str) -> FileInfo {
        FileInfo {
            path: path.to_owned(),
            content: content.as_bytes().to_vec(),
        }
    }

    // --- Module metadata ---

    #[test]
    fn test_describe() {
        let module = SecurityModule::new();
        let info = module.describe();
        assert_eq!(info.id, "security");
        assert_eq!(info.name, "Security Analysis");
        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.rules.len(), 9);
        assert!(info.languages.contains(&"go".to_owned()));
        assert!(info.languages.contains(&"python".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = SecurityModule::default();
        let info = module.describe();
        assert_eq!(info.id, "security");
    }

    // --- Full analysis integration ---

    #[test]
    fn test_analyze_go_sql_injection() {
        let module = SecurityModule::new();
        let files = vec![make_file(
            "handler.go",
            r#"package main

import (
    "database/sql"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    db.Query(query)
}
"#,
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let sql_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "sql-injection")
            .collect();
        assert!(
            !sql_findings.is_empty(),
            "should detect SQL injection via module analyze"
        );
    }

    #[test]
    fn test_analyze_python_with_secrets() {
        let module = SecurityModule::new();
        let files = vec![make_file(
            "config.py",
            "API_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let secret_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "hardcoded-secret")
            .collect();
        assert!(
            !secret_findings.is_empty(),
            "should detect AWS key in config.py"
        );
    }

    #[test]
    fn test_analyze_manifest() {
        let module = SecurityModule::new();
        let files = vec![make_file(
            "requirements.txt",
            "flask==2.3.0\nrequests==2.28.0\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let dep_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "vulnerable-dependency")
            .collect();
        assert!(
            !dep_findings.is_empty(),
            "should detect vulnerable deps in requirements.txt"
        );
    }

    #[test]
    fn test_analyze_empty_files() {
        let module = SecurityModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.metrics.files_analyzed, 0);
    }

    #[test]
    fn test_analyze_clean_code() {
        let module = SecurityModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(
            result.findings.is_empty(),
            "clean code should have no security findings"
        );
    }

    #[test]
    fn test_analyze_metrics_counters() {
        let module = SecurityModule::new();
        let files = vec![
            make_file(
                "handler.go",
                r#"package main

func handler(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
"#,
            ),
            make_file("config.py", "API_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"),
            make_file("requirements.txt", "flask==2.3.0\n"),
        ];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.metrics.counters.contains_key("sast_findings"));
        assert!(result.metrics.counters.contains_key("secret_findings"));
        assert!(result.metrics.counters.contains_key("dependency_findings"));
    }

    // --- Explain ---

    #[test]
    fn test_explain_all_rules() {
        let module = SecurityModule::new();
        let rule_ids = vec![
            "sql-injection",
            "command-injection",
            "xss",
            "ssrf",
            "path-traversal",
            "unsafe-deserialization",
            "hardcoded-secret",
            "high-entropy-string",
            "vulnerable-dependency",
        ];
        for rule_id in rule_ids {
            let explanation = module
                .explain(rule_id)
                .unwrap_or_else(|e| panic!("explain({rule_id}) failed: {e}"));
            assert_eq!(explanation.rule_id, rule_id);
            assert!(!explanation.description.is_empty());
            assert!(!explanation.rationale.is_empty());
            assert!(!explanation.suppression_syntax.is_empty());
        }
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = SecurityModule::new();
        let result = module.explain("nonexistent");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ChaffraError::RuleNotFound(_)));
    }

    // --- Fix ---

    #[test]
    fn test_fix_returns_manual_review() {
        let module = SecurityModule::new();
        let findings = vec![Finding {
            rule_id: "sql-injection".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Error,
            location: chaffra_core::diagnostic::Location {
                file: "test.go".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
        assert!(results[0].reason.contains("manual review"));
    }

    #[test]
    fn test_fix_dry_run_same_as_live() {
        let module = SecurityModule::new();
        let findings = vec![Finding {
            rule_id: "hardcoded-secret".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Error,
            location: chaffra_core::diagnostic::Location {
                file: "config.py".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }];
        let dry = module.fix(&findings, true).unwrap();
        let live = module.fix(&findings, false).unwrap();
        assert_eq!(dry.len(), live.len());
        // Both should not apply.
        assert!(!dry[0].applied);
        assert!(!live[0].applied);
    }

    // --- Helper function tests ---

    #[test]
    fn test_is_sast_rule() {
        let sast_rules = vec![
            "sql-injection",
            "command-injection",
            "xss",
            "ssrf",
            "path-traversal",
            "unsafe-deserialization",
        ];
        for rule in sast_rules {
            assert!(is_sast_rule(rule), "is_sast_rule({rule}) should be true");
        }
        assert!(!is_sast_rule("hardcoded-secret"));
        assert!(!is_sast_rule("vulnerable-dependency"));
    }

    #[test]
    fn test_is_secret_rule() {
        assert!(is_secret_rule("hardcoded-secret"));
        assert!(is_secret_rule("high-entropy-string"));
        assert!(!is_secret_rule("sql-injection"));
        assert!(!is_secret_rule("vulnerable-dependency"));
    }

    #[test]
    fn test_sast_findings_count_for_file() {
        let findings = vec![
            Finding {
                rule_id: "sql-injection".to_owned(),
                message: "test".to_owned(),
                severity: Severity::Error,
                location: chaffra_core::diagnostic::Location {
                    file: "handler.go".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            },
            Finding {
                rule_id: "hardcoded-secret".to_owned(),
                message: "test".to_owned(),
                severity: Severity::Error,
                location: chaffra_core::diagnostic::Location {
                    file: "handler.go".to_owned(),
                    start_line: 2,
                    end_line: 2,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            },
        ];
        assert_eq!(sast_findings_count_for_file(&findings, "handler.go"), 1);
        assert_eq!(sast_findings_count_for_file(&findings, "other.go"), 0);
    }
}
