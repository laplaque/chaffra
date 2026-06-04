//! Framework detection for Go and Python using tree-sitter.
//!
//! Detects framework-specific entry points (HTTP handlers, CLI commands, route
//! decorators) that should be considered "alive" by the dead-code module. Supports
//! Go frameworks (gin, echo, cobra) and Python frameworks (FastAPI, Django, Flask).

pub mod detect;
pub mod go;
pub mod python;

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use detect::FrameworkEntry;
use std::collections::HashMap;

/// The frameworks detection module.
///
/// Scans source files for framework-specific patterns and reports entry points
/// that should be marked alive for dead-code analysis.
pub struct FrameworksModule;

impl FrameworksModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FrameworksModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Rules provided by this module.
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "framework-entry-point",
        "Framework entry point detected",
        "A function or method serves as a framework entry point (HTTP handler, CLI command, route)",
        "frameworks",
    ),
    (
        "framework-detected",
        "Framework detected",
        "A framework was detected in the project (gin, echo, cobra, FastAPI, Django, Flask)",
        "frameworks",
    ),
];

impl AnalysisModule for FrameworksModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "frameworks".to_owned(),
            name: "Framework Detection".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: Severity::Info,
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
        let mut frameworks_seen: HashMap<String, bool> = HashMap::new();

        for file in files {
            let ext = file.path.rsplit('.').next().unwrap_or("");
            let language = match Language::from_extension(ext) {
                Some(lang) => lang,
                None => continue,
            };

            let entries = detect::detect_framework_entries(&file.content, language, &file.path);

            for entry in &entries {
                findings.push(Finding {
                    rule_id: "framework-entry-point".to_owned(),
                    message: format!(
                        "{} {} entry point: {}",
                        entry.framework, entry.kind, entry.name
                    ),
                    severity: Severity::Info,
                    location: Location {
                        file: file.path.clone(),
                        start_line: entry.line,
                        end_line: entry.line,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: entry.confidence,
                    actions: vec![],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("framework".to_owned(), entry.framework.clone());
                        m.insert("entry_kind".to_owned(), entry.kind.clone());
                        m.insert("alive".to_owned(), "true".to_owned());
                        m
                    },
                });

                frameworks_seen.insert(entry.framework.clone(), true);
            }
        }

        // Emit one finding per unique framework detected.
        for framework in frameworks_seen.keys() {
            findings.push(Finding {
                rule_id: "framework-detected".to_owned(),
                message: format!("Framework detected: {framework}"),
                severity: Severity::Info,
                location: Location {
                    file: String::new(),
                    start_line: 0,
                    end_line: 0,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("framework".to_owned(), framework.clone());
                    m
                },
            });
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: {
                    let mut c = HashMap::new();
                    c.insert(
                        "frameworks_detected".to_owned(),
                        frameworks_seen.len() as u64,
                    );
                    c
                },
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "framework-entry-point" => Ok(RuleExplanation {
                rule_id: "framework-entry-point".to_owned(),
                name: "Framework entry point detected".to_owned(),
                description: "A function or method serves as a framework entry point.".to_owned(),
                rationale: "Framework entry points (HTTP handlers, CLI commands, route decorators) \
                    are invoked by the framework at runtime, not by user code directly. They should \
                    be considered alive and not flagged as dead code."
                    .to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore framework-entry-point".to_owned(),
                examples: vec![
                    "r.GET(\"/path\", handlerFunc) // gin handler".to_owned(),
                    "@app.get(\"/path\") // FastAPI route".to_owned(),
                ],
            }),
            "framework-detected" => Ok(RuleExplanation {
                rule_id: "framework-detected".to_owned(),
                name: "Framework detected".to_owned(),
                description: "A framework was detected in the project.".to_owned(),
                rationale: "Detecting frameworks allows chaffra to understand entry point patterns \
                    and avoid false positives in dead-code analysis."
                    .to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore framework-detected".to_owned(),
                examples: vec![],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Framework detection is informational only; no fixes to apply.
        Ok(vec![])
    }
}

/// Extract framework entry points from files.
///
/// This is a convenience function for use by other modules (e.g. dead-code)
/// to determine which symbols should be considered alive.
pub fn get_alive_entry_points(files: &[FileInfo]) -> Vec<FrameworkEntry> {
    let mut entries = Vec::new();
    for file in files {
        let ext = file.path.rsplit('.').next().unwrap_or("");
        let language = match Language::from_extension(ext) {
            Some(lang) => lang,
            None => continue,
        };
        entries.extend(detect::detect_framework_entries(
            &file.content,
            language,
            &file.path,
        ));
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_describe() {
        let module = FrameworksModule::new();
        let info = module.describe();
        assert_eq!(info.id, "frameworks");
        assert!(info.languages.contains(&"go".to_owned()));
        assert!(info.languages.contains(&"python".to_owned()));
        assert_eq!(info.rules.len(), 2);
    }

    #[test]
    fn test_module_explain_entry_point() {
        let module = FrameworksModule::new();
        let explanation = module.explain("framework-entry-point").unwrap();
        assert_eq!(explanation.rule_id, "framework-entry-point");
        assert!(!explanation.examples.is_empty());
    }

    #[test]
    fn test_module_explain_detected() {
        let module = FrameworksModule::new();
        let explanation = module.explain("framework-detected").unwrap();
        assert_eq!(explanation.rule_id, "framework-detected");
    }

    #[test]
    fn test_module_explain_unknown() {
        let module = FrameworksModule::new();
        let result = module.explain("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_module_fix_is_noop() {
        let module = FrameworksModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_module_default() {
        let module = FrameworksModule::default();
        assert_eq!(module.describe().id, "frameworks");
    }

    #[test]
    fn test_analyze_gin_handler() {
        let module = FrameworksModule::new();
        let files = vec![FileInfo {
            path: "main.go".to_owned(),
            content: br#"package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/hello", helloHandler)
    r.POST("/users", createUser)
    r.Run()
}

func helloHandler(c *gin.Context) {
    c.JSON(200, gin.H{"msg": "hello"})
}

func createUser(c *gin.Context) {
    c.JSON(201, gin.H{"msg": "created"})
}
"#
            .to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let entry_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "framework-entry-point")
            .collect();
        assert!(
            entry_findings.len() >= 2,
            "should detect gin handler entry points: {entry_findings:?}"
        );
        // Should detect the gin framework.
        let framework_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "framework-detected")
            .collect();
        assert!(
            !framework_findings.is_empty(),
            "should detect gin framework"
        );
    }

    #[test]
    fn test_analyze_fastapi_routes() {
        let module = FrameworksModule::new();
        let files = vec![FileInfo {
            path: "app.py".to_owned(),
            content: br#"from fastapi import FastAPI

app = FastAPI()

@app.get("/hello")
def hello():
    return {"msg": "hello"}

@app.post("/users")
def create_user():
    return {"msg": "created"}
"#
            .to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let entry_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "framework-entry-point")
            .collect();
        assert!(
            entry_findings.len() >= 2,
            "should detect FastAPI route entry points: {entry_findings:?}"
        );
    }

    #[test]
    fn test_analyze_no_frameworks() {
        let module = FrameworksModule::new();
        let files = vec![FileInfo {
            path: "main.go".to_owned(),
            content: b"package main\n\nfunc main() {}\n".to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_skips_unknown_extensions() {
        let module = FrameworksModule::new();
        let files = vec![FileInfo {
            path: "main.rs".to_owned(),
            content: b"fn main() {}".to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_get_alive_entry_points_utility() {
        let files = vec![FileInfo {
            path: "app.py".to_owned(),
            content: br#"from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "hello"
"#
            .to_vec(),
        }];
        let entries = get_alive_entry_points(&files);
        assert!(!entries.is_empty(), "should find Flask entry points");
    }
}
