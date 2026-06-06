//! Cyclomatic and cognitive complexity metrics.
//!
//! Computes per-function complexity scores directly from tree-sitter ASTs.
//! Cyclomatic complexity counts independent control-flow paths; cognitive
//! complexity weights nesting depth to better reflect human comprehension cost.
//! Results feed into health scoring.

use chaffra_core::diagnostic::{
    AnalysisResult, FileHealthScore, FileInfo, Finding, FixResult, HealthGrade, Language, Location,
    ModuleInfo, ModuleMetrics, ProjectHealth, Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::parser;
use std::collections::HashMap;
use tree_sitter::Node;

/// Complexity analysis module with health scoring.
pub struct ComplexityModule;

impl ComplexityModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ComplexityModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-function complexity metrics.
#[derive(Debug, Clone)]
pub struct FunctionMetrics {
    pub name: String,
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub cyclomatic: u32,
    pub cognitive: u32,
    pub lines: u32,
    pub max_nesting: u32,
}

/// Compute all function metrics for a file.
pub fn compute_file_metrics(
    source: &[u8],
    language: Language,
    file: &str,
) -> Result<Vec<FunctionMetrics>> {
    // Languages without tree-sitter support cannot produce function metrics.
    if !language.has_tree_sitter_grammar() {
        return Ok(Vec::new());
    }

    let tree = parser::parse(source, language)?;
    let root = tree.root_node();
    let mut metrics = Vec::new();

    match language {
        Language::Go => collect_go_functions(root, source, file, &mut metrics),
        Language::Python => collect_python_functions(root, source, file, &mut metrics),
        _ => {} // Unreachable due to has_tree_sitter_grammar check above.
    }

    Ok(metrics)
}

/// Compute a health score for a file based on its function metrics.
pub fn compute_file_health(
    metrics: &[FunctionMetrics],
    file: &str,
    max_cyclomatic: u32,
    max_cognitive: u32,
) -> FileHealthScore {
    if metrics.is_empty() {
        return FileHealthScore {
            file: file.to_owned(),
            score: 100,
            grade: HealthGrade::A,
            cyclomatic_penalty: 0,
            cognitive_penalty: 0,
            size_penalty: 0,
            nesting_penalty: 0,
        };
    }

    let avg_cyclomatic: f64 =
        metrics.iter().map(|m| m.cyclomatic as f64).sum::<f64>() / metrics.len() as f64;
    let avg_cognitive: f64 =
        metrics.iter().map(|m| m.cognitive as f64).sum::<f64>() / metrics.len() as f64;
    let max_lines: u32 = metrics.iter().map(|m| m.lines).max().unwrap_or(0);
    let max_nesting: u32 = metrics.iter().map(|m| m.max_nesting).max().unwrap_or(0);

    // Penalties: each metric penalizes proportionally to how much it exceeds thresholds.
    let cyclomatic_penalty = if avg_cyclomatic > max_cyclomatic as f64 {
        ((avg_cyclomatic - max_cyclomatic as f64) * 3.0).min(30.0) as u32
    } else {
        0
    };

    let cognitive_penalty = if avg_cognitive > max_cognitive as f64 {
        ((avg_cognitive - max_cognitive as f64) * 3.0).min(30.0) as u32
    } else {
        0
    };

    let size_penalty = if max_lines > 100 {
        ((max_lines - 100) / 20).min(20)
    } else {
        0
    };

    let nesting_penalty = if max_nesting > 4 {
        ((max_nesting - 4) * 5).min(20)
    } else {
        0
    };

    let score = 100u32
        .saturating_sub(cyclomatic_penalty + cognitive_penalty + size_penalty + nesting_penalty);
    let grade = HealthGrade::from_score(score);

    FileHealthScore {
        file: file.to_owned(),
        score,
        grade,
        cyclomatic_penalty,
        cognitive_penalty,
        size_penalty,
        nesting_penalty,
    }
}

/// Compute project-level health from file scores.
pub fn compute_project_health(file_scores: &[FileHealthScore]) -> ProjectHealth {
    if file_scores.is_empty() {
        return ProjectHealth {
            score: 100,
            grade: HealthGrade::A,
            files: Vec::new(),
            total_files: 0,
        };
    }

    let total: u64 = file_scores.iter().map(|f| f.score as u64).sum();
    let score = (total / file_scores.len() as u64) as u32;
    let grade = HealthGrade::from_score(score);

    ProjectHealth {
        score,
        grade,
        files: file_scores.to_vec(),
        total_files: file_scores.len() as u64,
    }
}

// --- Go complexity ---

fn collect_go_functions(
    root: Node<'_>,
    source: &[u8],
    file: &str,
    metrics: &mut Vec<FunctionMetrics>,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_declaration" | "method_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = name_node.utf8_text(source).unwrap_or("").to_owned();
                    let body = child.child_by_field_name("body");
                    let cyclomatic = body.map(|b| compute_cyclomatic_go(b)).unwrap_or(1);
                    let cognitive = body.map(|b| compute_cognitive_go(b, 0)).unwrap_or(0);
                    let max_nesting = body.map(|b| compute_max_nesting(b, 0)).unwrap_or(0);
                    let lines = (child.end_position().row - child.start_position().row + 1) as u32;

                    metrics.push(FunctionMetrics {
                        name,
                        file: file.to_owned(),
                        start_line: child.start_position().row as u32 + 1,
                        end_line: child.end_position().row as u32 + 1,
                        cyclomatic,
                        cognitive,
                        lines,
                        max_nesting,
                    });
                }
            }
            _ => {}
        }
    }
}

fn compute_cyclomatic_go(node: Node<'_>) -> u32 {
    let mut complexity = 1; // Base path
    add_cyclomatic_go(node, &mut complexity);
    complexity
}

fn add_cyclomatic_go(node: Node<'_>, complexity: &mut u32) {
    match node.kind() {
        "if_statement" | "for_statement" | "expression_case" | "type_case" | "default_case" => {
            *complexity += 1;
        }
        "binary_expression" => {
            // Count && and || as additional paths.
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = op.kind();
                if op_text == "&&" || op_text == "||" {
                    *complexity += 1;
                }
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        add_cyclomatic_go(child, complexity);
    }
}

fn compute_cognitive_go(node: Node<'_>, nesting: u32) -> u32 {
    let mut total = 0;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "if_statement" | "for_statement" => {
                total += 1 + nesting; // increment + nesting penalty
                total += compute_cognitive_go(child, nesting + 1);
            }
            "expression_switch_statement" | "type_switch_statement" => {
                total += 1 + nesting;
                total += compute_cognitive_go(child, nesting + 1);
            }
            "binary_expression" => {
                if let Some(op) = child.child_by_field_name("operator") {
                    let op_text = op.kind();
                    if op_text == "&&" || op_text == "||" {
                        total += 1;
                    }
                }
                total += compute_cognitive_go(child, nesting);
            }
            _ => {
                total += compute_cognitive_go(child, nesting);
            }
        }
    }

    total
}

// --- Python complexity ---

fn collect_python_functions(
    root: Node<'_>,
    source: &[u8],
    file: &str,
    metrics: &mut Vec<FunctionMetrics>,
) {
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                extract_python_func_metrics(child, source, file, metrics);
            }
            "decorated_definition" => {
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "function_definition" {
                        extract_python_func_metrics(inner, source, file, metrics);
                    }
                }
            }
            _ => {}
        }
    }
}

fn extract_python_func_metrics(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    metrics: &mut Vec<FunctionMetrics>,
) {
    if let Some(name_node) = node.child_by_field_name("name") {
        let name = name_node.utf8_text(source).unwrap_or("").to_owned();
        let body = node.child_by_field_name("body");
        let cyclomatic = body.map(|b| compute_cyclomatic_python(b)).unwrap_or(1);
        let cognitive = body.map(|b| compute_cognitive_python(b, 0)).unwrap_or(0);
        let max_nesting = body.map(|b| compute_max_nesting(b, 0)).unwrap_or(0);
        let lines = (node.end_position().row - node.start_position().row + 1) as u32;

        metrics.push(FunctionMetrics {
            name,
            file: file.to_owned(),
            start_line: node.start_position().row as u32 + 1,
            end_line: node.end_position().row as u32 + 1,
            cyclomatic,
            cognitive,
            lines,
            max_nesting,
        });
    }
}

fn compute_cyclomatic_python(node: Node<'_>) -> u32 {
    let mut complexity = 1;
    add_cyclomatic_python(node, &mut complexity);
    complexity
}

fn add_cyclomatic_python(node: Node<'_>, complexity: &mut u32) {
    match node.kind() {
        "if_statement" | "elif_clause" | "for_statement" | "while_statement" | "except_clause"
        | "with_statement" => {
            *complexity += 1;
        }
        "boolean_operator" => {
            *complexity += 1;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        add_cyclomatic_python(child, complexity);
    }
}

fn compute_cognitive_python(node: Node<'_>, nesting: u32) -> u32 {
    let mut total = 0;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        match child.kind() {
            "if_statement" | "for_statement" | "while_statement" | "with_statement" => {
                total += 1 + nesting;
                total += compute_cognitive_python(child, nesting + 1);
            }
            "elif_clause" => {
                total += 1; // No nesting penalty for elif (same level as if).
                total += compute_cognitive_python(child, nesting + 1);
            }
            "except_clause" => {
                total += 1 + nesting;
                total += compute_cognitive_python(child, nesting + 1);
            }
            "boolean_operator" => {
                total += 1;
                total += compute_cognitive_python(child, nesting);
            }
            _ => {
                total += compute_cognitive_python(child, nesting);
            }
        }
    }

    total
}

// --- Shared helpers ---

fn compute_max_nesting(node: Node<'_>, current: u32) -> u32 {
    let mut max = current;
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        let nested = match child.kind() {
            "if_statement"
            | "for_statement"
            | "while_statement"
            | "with_statement"
            | "expression_switch_statement"
            | "type_switch_statement"
            | "except_clause" => compute_max_nesting(child, current + 1),
            _ => compute_max_nesting(child, current),
        };
        max = max.max(nested);
    }

    max
}

fn detect_language(path: &str) -> Option<Language> {
    if path.ends_with(".go") {
        Some(Language::Go)
    } else if path.ends_with(".py") {
        Some(Language::Python)
    } else {
        None
    }
}

impl AnalysisModule for ComplexityModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "complexity".to_owned(),
            name: "Complexity & Health Scoring".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec![
                "analyze".to_owned(),
                "explain".to_owned(),
                "health".to_owned(),
            ],
            rules: vec![
                Rule {
                    id: "high-cyclomatic".to_owned(),
                    name: "High cyclomatic complexity".to_owned(),
                    description: "Function exceeds cyclomatic complexity threshold".to_owned(),
                    default_severity: Severity::Warning,
                    category: "complexity".to_owned(),
                },
                Rule {
                    id: "high-cognitive".to_owned(),
                    name: "High cognitive complexity".to_owned(),
                    description: "Function exceeds cognitive complexity threshold".to_owned(),
                    default_severity: Severity::Warning,
                    category: "complexity".to_owned(),
                },
                Rule {
                    id: "low-health-score".to_owned(),
                    name: "Low health score".to_owned(),
                    description: "File health score is below threshold".to_owned(),
                    default_severity: Severity::Warning,
                    category: "complexity".to_owned(),
                },
            ],
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let max_cyclomatic: u32 = config
            .get("max-cyclomatic")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20);
        let max_cognitive: u32 = config
            .get("max-cognitive")
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);
        let min_score: u32 = config
            .get("min-score")
            .and_then(|v| v.parse().ok())
            .unwrap_or(70);

        let mut findings = Vec::new();
        let mut total_functions = 0u64;

        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l) => l,
                None => continue,
            };

            let func_metrics = compute_file_metrics(&file.content, lang, &file.path)?;
            total_functions += func_metrics.len() as u64;

            for fm in &func_metrics {
                if fm.cyclomatic > max_cyclomatic {
                    findings.push(Finding {
                        rule_id: "high-cyclomatic".to_owned(),
                        message: format!(
                            "function `{}` has cyclomatic complexity {} (threshold: {})",
                            fm.name, fm.cyclomatic, max_cyclomatic
                        ),
                        severity: Severity::Warning,
                        location: Location {
                            file: fm.file.clone(),
                            start_line: fm.start_line,
                            end_line: fm.end_line,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: 1.0,
                        actions: vec![],
                        metadata: {
                            let mut m = HashMap::new();
                            m.insert("cyclomatic".to_owned(), fm.cyclomatic.to_string());
                            m
                        },
                    });
                }

                if fm.cognitive > max_cognitive {
                    findings.push(Finding {
                        rule_id: "high-cognitive".to_owned(),
                        message: format!(
                            "function `{}` has cognitive complexity {} (threshold: {})",
                            fm.name, fm.cognitive, max_cognitive
                        ),
                        severity: Severity::Warning,
                        location: Location {
                            file: fm.file.clone(),
                            start_line: fm.start_line,
                            end_line: fm.end_line,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: 1.0,
                        actions: vec![],
                        metadata: {
                            let mut m = HashMap::new();
                            m.insert("cognitive".to_owned(), fm.cognitive.to_string());
                            m
                        },
                    });
                }
            }

            // Health score finding.
            let health =
                compute_file_health(&func_metrics, &file.path, max_cyclomatic, max_cognitive);
            if health.score < min_score {
                findings.push(Finding {
                    rule_id: "low-health-score".to_owned(),
                    message: format!(
                        "file `{}` has health score {} ({}) below threshold {}",
                        file.path, health.score, health.grade, min_score
                    ),
                    severity: Severity::Warning,
                    location: Location {
                        file: file.path.clone(),
                        start_line: 1,
                        end_line: 1,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 1.0,
                    actions: vec![],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("score".to_owned(), health.score.to_string());
                        m.insert("grade".to_owned(), health.grade.to_string());
                        m
                    },
                });
            }
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: {
                    let mut c = HashMap::new();
                    c.insert("functions_analyzed".to_owned(), total_functions);
                    c
                },
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "high-cyclomatic" => Ok(RuleExplanation {
                rule_id: "high-cyclomatic".to_owned(),
                name: "High cyclomatic complexity".to_owned(),
                description: "Function has too many independent paths through its code.".to_owned(),
                rationale: "High cyclomatic complexity correlates with bugs and makes testing difficult. Each branch requires at least one test case.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore high-cyclomatic".to_owned(),
                examples: vec![
                    "A function with 10 if/else branches has cyclomatic complexity >= 11.".to_owned(),
                ],
            }),
            "high-cognitive" => Ok(RuleExplanation {
                rule_id: "high-cognitive".to_owned(),
                name: "High cognitive complexity".to_owned(),
                description: "Function is too hard for a human to understand due to nesting and branching.".to_owned(),
                rationale: "Cognitive complexity penalizes deeply nested structures more than flat ones, better reflecting real comprehension cost.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore high-cognitive".to_owned(),
                examples: vec![],
            }),
            "low-health-score" => Ok(RuleExplanation {
                rule_id: "low-health-score".to_owned(),
                name: "Low health score".to_owned(),
                description: "File composite health score is below the configured threshold.".to_owned(),
                rationale: "Health score combines cyclomatic, cognitive, size, and nesting penalties into a single 0-100 metric. Low scores indicate files that need refactoring.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore low-health-score".to_owned(),
                examples: vec![],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Complexity issues cannot be auto-fixed.
        Ok(vec![])
    }
}

/// Convenience: analyze files and produce a ProjectHealth summary.
pub fn analyze_project_health(
    files: &[FileInfo],
    max_cyclomatic: u32,
    max_cognitive: u32,
) -> Result<ProjectHealth> {
    let mut file_scores = Vec::new();

    for file in files {
        let lang = match detect_language(&file.path) {
            Some(l) => l,
            None => continue,
        };

        let metrics = compute_file_metrics(&file.content, lang, &file.path)?;
        let health = compute_file_health(&metrics, &file.path, max_cyclomatic, max_cognitive);
        file_scores.push(health);
    }

    Ok(compute_project_health(&file_scores))
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

    #[test]
    fn test_describe() {
        let module = ComplexityModule::new();
        let info = module.describe();
        assert_eq!(info.id, "complexity");
        assert_eq!(info.rules.len(), 3);
    }

    #[test]
    fn test_simple_go_function() {
        let src = b"package main\n\nfunc simple() {\n\tx := 1\n\t_ = x\n}\n";
        let metrics = compute_file_metrics(src, Language::Go, "test.go").unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "simple");
        assert_eq!(metrics[0].cyclomatic, 1); // No branches
        assert_eq!(metrics[0].cognitive, 0);
    }

    #[test]
    fn test_go_function_with_if() {
        let src = b"package main\n\nfunc check(x int) {\n\tif x > 0 {\n\t\t_ = x\n\t}\n}\n";
        let metrics = compute_file_metrics(src, Language::Go, "test.go").unwrap();
        assert_eq!(metrics.len(), 1);
        assert!(metrics[0].cyclomatic >= 2); // Base + 1 if
    }

    #[test]
    fn test_python_simple() {
        let src = b"def simple():\n    x = 1\n";
        let metrics = compute_file_metrics(src, Language::Python, "test.py").unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cyclomatic, 1);
    }

    #[test]
    fn test_python_with_branches() {
        let src =
            b"def check(x):\n    if x > 0:\n        return True\n    else:\n        return False\n";
        let metrics = compute_file_metrics(src, Language::Python, "test.py").unwrap();
        assert_eq!(metrics.len(), 1);
        assert!(metrics[0].cyclomatic >= 2);
    }

    #[test]
    fn test_health_score_simple() {
        let metrics = vec![FunctionMetrics {
            name: "simple".to_owned(),
            file: "test.go".to_owned(),
            start_line: 1,
            end_line: 5,
            cyclomatic: 1,
            cognitive: 0,
            lines: 5,
            max_nesting: 0,
        }];
        let health = compute_file_health(&metrics, "test.go", 20, 15);
        assert_eq!(health.score, 100);
        assert_eq!(health.grade, HealthGrade::A);
    }

    #[test]
    fn test_health_score_complex() {
        let metrics = vec![FunctionMetrics {
            name: "complex".to_owned(),
            file: "test.go".to_owned(),
            start_line: 1,
            end_line: 200,
            cyclomatic: 30,
            cognitive: 25,
            lines: 200,
            max_nesting: 8,
        }];
        let health = compute_file_health(&metrics, "test.go", 20, 15);
        assert!(
            health.score < 70,
            "complex function should have low score: {}",
            health.score
        );
        assert!(matches!(health.grade, HealthGrade::D | HealthGrade::F));
    }

    #[test]
    fn test_project_health() {
        let scores = vec![
            FileHealthScore {
                file: "a.go".to_owned(),
                score: 90,
                grade: HealthGrade::A,
                cyclomatic_penalty: 0,
                cognitive_penalty: 0,
                size_penalty: 0,
                nesting_penalty: 0,
            },
            FileHealthScore {
                file: "b.go".to_owned(),
                score: 80,
                grade: HealthGrade::B,
                cyclomatic_penalty: 10,
                cognitive_penalty: 10,
                size_penalty: 0,
                nesting_penalty: 0,
            },
        ];
        let project = compute_project_health(&scores);
        assert_eq!(project.score, 85);
        assert_eq!(project.grade, HealthGrade::B);
    }

    #[test]
    fn test_grade_boundaries() {
        assert_eq!(HealthGrade::from_score(100), HealthGrade::A);
        assert_eq!(HealthGrade::from_score(90), HealthGrade::A);
        assert_eq!(HealthGrade::from_score(89), HealthGrade::B);
        assert_eq!(HealthGrade::from_score(80), HealthGrade::B);
        assert_eq!(HealthGrade::from_score(79), HealthGrade::C);
        assert_eq!(HealthGrade::from_score(70), HealthGrade::C);
        assert_eq!(HealthGrade::from_score(69), HealthGrade::D);
        assert_eq!(HealthGrade::from_score(60), HealthGrade::D);
        assert_eq!(HealthGrade::from_score(59), HealthGrade::F);
        assert_eq!(HealthGrade::from_score(0), HealthGrade::F);
    }

    #[test]
    fn test_analyze_finds_high_complexity() {
        let module = ComplexityModule::new();
        // Set low thresholds to trigger findings.
        let mut config = HashMap::new();
        config.insert("max-cyclomatic".to_owned(), "1".to_owned());
        config.insert("max-cognitive".to_owned(), "0".to_owned());

        let files = vec![make_file(
            "test.go",
            "package main\n\nfunc check(x int) {\n\tif x > 0 {\n\t\t_ = x\n\t}\n}\n",
        )];
        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should find complexity issues with low thresholds"
        );
    }

    #[test]
    fn test_empty_project_health() {
        let health = compute_project_health(&[]);
        assert_eq!(health.score, 100);
        assert_eq!(health.grade, HealthGrade::A);
    }

    #[test]
    fn test_default_module() {
        let module = ComplexityModule::default();
        assert_eq!(module.describe().id, "complexity");
    }

    #[test]
    fn test_empty_file_health() {
        let health = compute_file_health(&[], "empty.go", 20, 15);
        assert_eq!(health.score, 100);
        assert_eq!(health.grade, HealthGrade::A);
    }

    #[test]
    fn test_explain_rule() {
        let module = ComplexityModule::new();
        let explanation = module.explain("high-cyclomatic").unwrap();
        assert_eq!(explanation.rule_id, "high-cyclomatic");
        assert!(!explanation.description.is_empty());

        let explanation = module.explain("high-cognitive").unwrap();
        assert_eq!(explanation.rule_id, "high-cognitive");

        let explanation = module.explain("low-health-score").unwrap();
        assert_eq!(explanation.rule_id, "low-health-score");

        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_analyze_project_health() {
        let files = vec![make_file(
            "simple.go",
            "package main\n\nfunc simple() {\n\tx := 1\n\t_ = x\n}\n",
        )];
        let health = analyze_project_health(&files, 20, 15).unwrap();
        assert!(health.score >= 80);
    }

    #[test]
    fn test_analyze_project_health_empty() {
        let files: Vec<FileInfo> = vec![];
        let health = analyze_project_health(&files, 20, 15).unwrap();
        assert_eq!(health.score, 100);
    }

    #[test]
    fn test_analyze_skips_unsupported_language() {
        let module = ComplexityModule::new();
        let files = vec![make_file("test.rs", "fn main() {}")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_finds_high_cognitive() {
        let module = ComplexityModule::new();
        let mut config = HashMap::new();
        config.insert("max-cognitive".to_owned(), "0".to_owned());
        config.insert("max-cyclomatic".to_owned(), "100".to_owned());

        let files = vec![make_file(
            "nested.go",
            "package main\n\nfunc nested(x int) {\n\tif x > 0 {\n\t\tif x > 1 {\n\t\t\t_ = x\n\t\t}\n\t}\n}\n",
        )];
        let result = module.analyze(&files, &config).unwrap();
        let cognitive_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "high-cognitive")
            .collect();
        assert!(
            !cognitive_findings.is_empty(),
            "should find high-cognitive with threshold 0"
        );
    }

    #[test]
    fn test_analyze_finds_low_health_score() {
        let module = ComplexityModule::new();
        let mut config = HashMap::new();
        config.insert("min-score".to_owned(), "100".to_owned());
        config.insert("max-cyclomatic".to_owned(), "1".to_owned());
        config.insert("max-cognitive".to_owned(), "0".to_owned());

        let files = vec![make_file(
            "complex.go",
            "package main\n\nfunc complex(x int, y int) int {\n\tif x > 0 {\n\t\tif y > 0 {\n\t\t\treturn x + y\n\t\t}\n\t\treturn x\n\t}\n\treturn y\n}\n",
        )];
        let result = module.analyze(&files, &config).unwrap();
        let health_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "low-health-score")
            .collect();
        assert!(
            !health_findings.is_empty(),
            "should find low-health-score with threshold 100"
        );
    }

    #[test]
    fn test_fix_returns_empty() {
        let module = ComplexityModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_python_complexity_with_nesting() {
        let src = b"def deep(x):\n    if x > 0:\n        for i in range(x):\n            if i > 5:\n                while i > 0:\n                    i -= 1\n";
        let metrics = compute_file_metrics(src, Language::Python, "deep.py").unwrap();
        assert_eq!(metrics.len(), 1);
        assert!(
            metrics[0].cyclomatic >= 4,
            "deeply nested should have high cyclomatic: {}",
            metrics[0].cyclomatic
        );
        assert!(
            metrics[0].cognitive > 0,
            "deeply nested should have non-zero cognitive"
        );
        assert!(
            metrics[0].max_nesting >= 3,
            "deeply nested should have max_nesting >= 3: {}",
            metrics[0].max_nesting
        );
    }

    #[test]
    fn test_go_switch_complexity() {
        let src = b"package main\n\nfunc sw(x int) int {\n\tswitch x {\n\tcase 1:\n\t\treturn 1\n\tcase 2:\n\t\treturn 2\n\tdefault:\n\t\treturn 0\n\t}\n}\n";
        let metrics = compute_file_metrics(src, Language::Go, "sw.go").unwrap();
        assert_eq!(metrics.len(), 1);
        assert!(
            metrics[0].cyclomatic >= 3,
            "switch with cases should have cyclomatic >= 3: {}",
            metrics[0].cyclomatic
        );
    }

    #[test]
    fn test_detect_language_fn() {
        assert_eq!(detect_language("foo.go"), Some(Language::Go));
        assert_eq!(detect_language("bar.py"), Some(Language::Python));
        assert_eq!(detect_language("baz.rs"), None);
        assert_eq!(detect_language("test.js"), None);
    }

    #[test]
    fn test_python_decorated_function_metrics() {
        let src = b"def decorator(f):\n    return f\n\n@decorator\ndef decorated():\n    if True:\n        pass\n";
        let metrics = compute_file_metrics(src, Language::Python, "deco.py").unwrap();
        // Should find the top-level decorator function.
        assert!(
            !metrics.is_empty(),
            "should extract metrics from decorated function"
        );
    }

    #[test]
    fn test_go_method_complexity() {
        let src = b"package main\n\ntype S struct{}\n\nfunc (s S) Method(x int) {\n\tif x > 0 {\n\t\t_ = x\n\t}\n}\n";
        let metrics = compute_file_metrics(src, Language::Go, "method.go").unwrap();
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "Method");
        assert!(metrics[0].cyclomatic >= 2);
    }

    #[test]
    fn test_analyze_with_default_config() {
        let module = ComplexityModule::new();
        let files = vec![make_file(
            "simple.go",
            "package main\n\nfunc simple() {\n\tx := 1\n\t_ = x\n}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(
            result.findings.is_empty(),
            "simple function should have no findings with default thresholds"
        );
        assert_eq!(result.metrics.files_analyzed, 1);
    }

    #[test]
    fn test_python_try_except_complexity() {
        let src = b"def risky():\n    try:\n        x = 1\n    except ValueError:\n        x = 2\n    except Exception:\n        x = 3\n";
        let metrics = compute_file_metrics(src, Language::Python, "risky.py").unwrap();
        assert_eq!(metrics.len(), 1);
        assert!(
            metrics[0].cyclomatic >= 3,
            "function with try/except should have cyclomatic >= 3: {}",
            metrics[0].cyclomatic
        );
    }
}
