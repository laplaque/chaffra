//! Dead code detection engine.
//!
//! Identifies unreachable or unused symbols -- functions, types, imports, and entire
//! files -- by building a reference graph from parsed ASTs and finding nodes with no
//! live path from a declared entry point.

use chaffra_core::diagnostic::{
    Action, AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo,
    ModuleMetrics, Rule, RuleExplanation, Severity, TextEdit,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::graph::ImportGraph;
use chaffra_parse::parser;
use chaffra_parse::suppression;
use chaffra_parse::symbols::{self, Symbol, SymbolKind};
use std::collections::{HashMap, HashSet};

/// Dead code analysis module.
pub struct DeadCodeModule;

impl DeadCodeModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DeadCodeModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Rules provided by this module.
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "unused-function",
        "Unused function",
        "Function is defined but never called or referenced",
        "dead-code",
    ),
    (
        "unused-type",
        "Unused type",
        "Type is defined but never used",
        "dead-code",
    ),
    (
        "unused-import",
        "Unused import",
        "Import is declared but no imported name is used",
        "dead-code",
    ),
    (
        "unused-file",
        "Unused file",
        "File contains no symbols referenced by any other file",
        "dead-code",
    ),
    (
        "stale-suppression",
        "Stale suppression",
        "Suppression comment no longer applies to any finding",
        "dead-code",
    ),
];

impl AnalysisModule for DeadCodeModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "dead-code".to_owned(),
            name: "Dead Code Detection".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned(), "fix".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: Severity::Warning,
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
        let mut graph = ImportGraph::new();
        let mut all_suppressions: HashMap<String, Vec<suppression::Suppression>> = HashMap::new();
        let mut file_languages: HashMap<String, Language> = HashMap::new();

        // Parse all files and build the graph.
        for file in files {
            let lang = detect_language(&file.path);
            let lang = match lang {
                Some(l) => l,
                None => continue,
            };
            file_languages.insert(file.path.clone(), lang);

            let tree = parser::parse(&file.content, lang)?;
            let syms = symbols::extract_symbols(&tree, &file.content, lang, &file.path);
            let imports = symbols::extract_imports(&tree, &file.content, lang);
            let refs = symbols::extract_references(&tree, &file.content, lang, &file.path);

            graph.add_file(&file.path, syms, imports, refs);

            let source_str = String::from_utf8_lossy(&file.content);
            let supps = suppression::scan_suppressions(&source_str, lang);
            all_suppressions.insert(file.path.clone(), supps);
        }

        let mut findings = Vec::new();

        // Determine alive symbols via entry point and reference analysis.
        let alive = compute_alive_symbols(&graph, &file_languages);

        // Find unused symbols.
        for node in graph.nodes.values() {
            let lang = match file_languages.get(&node.file) {
                Some(l) => *l,
                None => continue,
            };
            let suppressions = all_suppressions
                .get(&node.file)
                .cloned()
                .unwrap_or_default();

            for sym in &node.symbols {
                if alive.contains(&(sym.file.clone(), sym.name.clone())) {
                    continue;
                }

                let rule_id = match sym.kind {
                    SymbolKind::Function => "unused-function",
                    SymbolKind::Type => "unused-type",
                    _ => continue,
                };

                // Check suppression.
                if suppression::is_suppressed(&suppressions, sym.start_line, rule_id) {
                    continue;
                }

                let confidence = if is_directly_referenced(&sym.name, &graph, &sym.file) {
                    0.8 // Referenced somewhere but possibly transitively dead
                } else {
                    1.0 // Not referenced anywhere
                };

                findings.push(Finding {
                    rule_id: rule_id.to_owned(),
                    message: format!("{} `{}` is never used", sym.kind, sym.name),
                    severity: Severity::Warning,
                    location: Location {
                        file: sym.file.clone(),
                        start_line: sym.start_line,
                        end_line: sym.end_line,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence,
                    actions: vec![Action {
                        description: format!("Remove {} `{}`", sym.kind, sym.name),
                        auto_fixable: true,
                        edits: vec![TextEdit {
                            file: sym.file.clone(),
                            start_line: sym.start_line,
                            end_line: sym.end_line,
                            new_text: String::new(),
                        }],
                    }],
                    metadata: HashMap::new(),
                });
            }

            // Check unused imports.
            let all_refs: HashSet<String> =
                node.references.iter().map(|r| r.name.clone()).collect();

            for imp in &node.imports {
                // For Go: the package name from the import path is used as identifier.
                let import_used = match lang {
                    Language::Go => {
                        let pkg_name = imp
                            .alias
                            .as_deref()
                            .unwrap_or_else(|| imp.path.rsplit('/').next().unwrap_or(&imp.path));
                        all_refs.contains(pkg_name)
                    }
                    Language::Python => {
                        if imp.names.is_empty() {
                            // import X / import X as alias -- check alias first, then basename
                            let used_name = imp.alias.as_deref().unwrap_or_else(|| {
                                imp.path.rsplit('.').next().unwrap_or(&imp.path)
                            });
                            all_refs.contains(used_name)
                        } else {
                            // from X import Y / from X import Y as Z
                            // names already contain the locally-used name (alias when present)
                            imp.names.iter().any(|n| all_refs.contains(n))
                        }
                    }
                };

                if !import_used {
                    if suppression::is_suppressed(&suppressions, imp.line, "unused-import") {
                        continue;
                    }

                    findings.push(Finding {
                        rule_id: "unused-import".to_owned(),
                        message: format!("import `{}` is never used", imp.path),
                        severity: Severity::Warning,
                        location: Location {
                            file: node.file.clone(),
                            start_line: imp.line,
                            end_line: imp.line,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: 1.0,
                        actions: vec![Action {
                            description: format!("Remove import `{}`", imp.path),
                            auto_fixable: true,
                            edits: vec![TextEdit {
                                file: node.file.clone(),
                                start_line: imp.line,
                                end_line: imp.line,
                                new_text: String::new(),
                            }],
                        }],
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        // Check for unused files (all symbols in the file are unused).
        for node in graph.nodes.values() {
            if node.symbols.is_empty() {
                continue;
            }
            let all_unused = node
                .symbols
                .iter()
                .all(|s| !alive.contains(&(s.file.clone(), s.name.clone())));
            if all_unused && !is_entry_file(&node.file) {
                let suppressions = all_suppressions
                    .get(&node.file)
                    .cloned()
                    .unwrap_or_default();
                if !suppression::is_suppressed(&suppressions, 1, "unused-file") {
                    findings.push(Finding {
                        rule_id: "unused-file".to_owned(),
                        message: format!("file `{}` contains no used symbols", node.file),
                        severity: Severity::Info,
                        location: Location {
                            file: node.file.clone(),
                            start_line: 1,
                            end_line: 1,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: 0.8,
                        actions: vec![],
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        // Check for stale suppressions.
        for (file, suppressions) in &all_suppressions {
            for supp in suppressions {
                let applies = findings.iter().any(|f| {
                    f.location.file == *file
                        && (f.location.start_line == supp.line
                            || f.location.start_line == supp.line + 1)
                });
                if !applies {
                    findings.push(Finding {
                        rule_id: "stale-suppression".to_owned(),
                        message: "suppression comment does not apply to any finding".to_owned(),
                        severity: Severity::Info,
                        location: Location {
                            file: file.clone(),
                            start_line: supp.line,
                            end_line: supp.line,
                            start_column: 0,
                            end_column: 0,
                        },
                        confidence: 1.0,
                        actions: vec![Action {
                            description: "Remove stale suppression comment".to_owned(),
                            auto_fixable: true,
                            edits: vec![TextEdit {
                                file: file.clone(),
                                start_line: supp.line,
                                end_line: supp.line,
                                new_text: String::new(),
                            }],
                        }],
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: HashMap::new(),
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "unused-function" => Ok(RuleExplanation {
                rule_id: "unused-function".to_owned(),
                name: "Unused function".to_owned(),
                description: "Detects functions that are defined but never called or referenced."
                    .to_owned(),
                rationale: "Unused functions increase maintenance burden and cognitive load. They may also indicate incomplete refactoring.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore unused-function".to_owned(),
                examples: vec![
                    "func helper() {} // never called".to_owned(),
                    "def _unused(): pass  # never called".to_owned(),
                ],
            }),
            "unused-type" => Ok(RuleExplanation {
                rule_id: "unused-type".to_owned(),
                name: "Unused type".to_owned(),
                description: "Detects types or classes that are defined but never instantiated or referenced.".to_owned(),
                rationale: "Unused types clutter the codebase and may confuse readers.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore unused-type".to_owned(),
                examples: vec![
                    "type OldConfig struct {} // never used".to_owned(),
                ],
            }),
            "unused-import" => Ok(RuleExplanation {
                rule_id: "unused-import".to_owned(),
                name: "Unused import".to_owned(),
                description: "Detects imports that are declared but no imported name is used.".to_owned(),
                rationale: "Unused imports slow compilation (Go) and clutter the namespace.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore unused-import".to_owned(),
                examples: vec![
                    "import \"fmt\" // fmt never used".to_owned(),
                ],
            }),
            "unused-file" => Ok(RuleExplanation {
                rule_id: "unused-file".to_owned(),
                name: "Unused file".to_owned(),
                description: "Detects files where all symbols are unreferenced.".to_owned(),
                rationale: "Files with no live symbols are dead weight in the repository.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "// chaffra:ignore unused-file".to_owned(),
                examples: vec![],
            }),
            "stale-suppression" => Ok(RuleExplanation {
                rule_id: "stale-suppression".to_owned(),
                name: "Stale suppression".to_owned(),
                description: "A chaffra:ignore comment that no longer applies to any finding.".to_owned(),
                rationale: "Stale suppressions mask future issues and clutter the code.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "N/A".to_owned(),
                examples: vec![],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
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
                continue;
            }

            let action = &finding.actions[0];
            if dry_run {
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: false,
                    edits: action.edits.clone(),
                    reason: "dry run".to_owned(),
                });
            } else {
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: true,
                    edits: action.edits.clone(),
                    reason: "applied".to_owned(),
                });
            }
        }
        Ok(results)
    }
}

/// Compute the set of alive (file, symbol_name) pairs via entry point analysis.
fn compute_alive_symbols(
    graph: &ImportGraph,
    file_languages: &HashMap<String, Language>,
) -> HashSet<(String, String)> {
    let mut alive: HashSet<(String, String)> = HashSet::new();
    let mut worklist: Vec<(String, String)> = Vec::new();

    // Seed entry points.
    for node in graph.nodes.values() {
        let lang = match file_languages.get(&node.file) {
            Some(l) => *l,
            None => continue,
        };

        for sym in &node.symbols {
            if is_entry_point(sym, lang, &node.file) {
                let key = (sym.file.clone(), sym.name.clone());
                if alive.insert(key.clone()) {
                    worklist.push(key);
                }
            }
        }
    }

    // Fixed-point iteration: trace references from alive symbols.
    while let Some((file, _name)) = worklist.pop() {
        // Find all references made from the file containing this symbol.
        if let Some(node) = graph.nodes.get(&file) {
            for reference in &node.references {
                // Find the symbol this reference points to.
                for other_node in graph.nodes.values() {
                    for sym in &other_node.symbols {
                        if sym.name == reference.name {
                            let key = (sym.file.clone(), sym.name.clone());
                            if alive.insert(key.clone()) {
                                worklist.push(key);
                            }
                        }
                    }
                }
            }
        }
    }

    alive
}

/// Check if a symbol is an entry point.
fn is_entry_point(sym: &Symbol, lang: Language, file: &str) -> bool {
    match lang {
        Language::Go => {
            // main and init functions are always entry points.
            if sym.name == "main" || sym.name == "init" {
                return true;
            }
            // Test* and Benchmark* functions are entry points.
            if sym.name.starts_with("Test") || sym.name.starts_with("Benchmark") {
                return true;
            }
            // Exported names in non-main packages are alive (public API).
            // We detect main package by checking if file has "main" in the path
            // or by checking the first line. For simplicity, exported = alive in Go.
            if sym.exported && sym.kind == SymbolKind::Function {
                return true;
            }
            // Exported types are entry points too.
            if sym.exported && sym.kind == SymbolKind::Type {
                return true;
            }
            false
        }
        Language::Python => {
            // __init__.py files have all top-level symbols as entry points.
            if file.ends_with("__init__.py") {
                return true;
            }
            // test_* functions are entry points.
            if sym.name.starts_with("test_") {
                return true;
            }
            // Public symbols are entry points.
            if sym.exported {
                return true;
            }
            false
        }
    }
}

/// Check if a file is an entry point file.
fn is_entry_file(file: &str) -> bool {
    let name = file.rsplit('/').next().unwrap_or(file);
    name == "main.go" || name == "__init__.py" || name == "__main__.py"
}

/// Check if a symbol name is directly referenced in any other file.
fn is_directly_referenced(name: &str, graph: &ImportGraph, defining_file: &str) -> bool {
    for node in graph.nodes.values() {
        if node.file == defining_file {
            continue;
        }
        if node.references.iter().any(|r| r.name == name) {
            return true;
        }
    }
    false
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
        let module = DeadCodeModule::new();
        let info = module.describe();
        assert_eq!(info.id, "dead-code");
        assert_eq!(info.rules.len(), 5);
    }

    #[test]
    fn test_go_unused_function() {
        let module = DeadCodeModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {}\n\nfunc unused() {}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        // main is an entry point, unused is not referenced.
        // But unused is unexported so it should be found.
        let unused_funcs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unused-function")
            .collect();
        assert!(!unused_funcs.is_empty(), "should find unused function");
    }

    #[test]
    fn test_go_used_function() {
        let module = DeadCodeModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {\n\thelper()\n}\n\nfunc helper() {}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unused_funcs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unused-function" && f.message.contains("helper"))
            .collect();
        assert!(
            unused_funcs.is_empty(),
            "helper should not be flagged as unused"
        );
    }

    #[test]
    fn test_python_unused_function() {
        let module = DeadCodeModule::new();
        let files = vec![make_file(
            "app.py",
            "def _unused():\n    pass\n\ndef _also_unused():\n    pass\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unused_funcs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unused-function")
            .collect();
        assert!(
            !unused_funcs.is_empty(),
            "should find unused Python functions"
        );
    }

    #[test]
    fn test_unused_import() {
        let module = DeadCodeModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nimport \"fmt\"\n\nfunc main() {}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unused_imports: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unused-import")
            .collect();
        assert!(!unused_imports.is_empty(), "should find unused import");
    }

    #[test]
    fn test_suppression() {
        let module = DeadCodeModule::new();
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {}\n\n// chaffra:ignore unused-function\nfunc unused() {}\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let unused_funcs: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unused-function")
            .collect();
        assert!(
            unused_funcs.is_empty(),
            "suppressed function should not be flagged"
        );
    }

    #[test]
    fn test_explain_known_rule() {
        let module = DeadCodeModule::new();
        let explanation = module.explain("unused-function").unwrap();
        assert_eq!(explanation.rule_id, "unused-function");
        assert!(!explanation.description.is_empty());
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = DeadCodeModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_fix_dry_run() {
        let module = DeadCodeModule::new();
        let findings = vec![Finding {
            rule_id: "unused-function".to_owned(),
            message: "unused".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 1,
                end_line: 2,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![Action {
                description: "Remove function".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "test.go".to_owned(),
                    start_line: 1,
                    end_line: 2,
                    new_text: String::new(),
                }],
            }],
            metadata: HashMap::new(),
        }];
        let results = module.fix(&findings, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
        assert_eq!(results[0].reason, "dry run");
    }

    #[test]
    fn test_python_import_alias_not_flagged() {
        let cases = vec![
            (
                "import numpy as np\n\narr = np.array([1])\n",
                "numpy",
                false,
            ),
            ("import os\n\nx = 1\n", "os", true),
        ];
        let module = DeadCodeModule::new();
        for (code, import_path, should_flag) in &cases {
            let files = vec![make_file("test.py", code)];
            let result = module.analyze(&files, &HashMap::new()).unwrap();
            let needle = format!("`{import_path}`");
            let flagged: Vec<_> = result
                .findings
                .iter()
                .filter(|f| f.rule_id == "unused-import" && f.message.contains(&needle))
                .collect();
            if *should_flag {
                assert!(
                    !flagged.is_empty(),
                    "import {import_path} should be flagged in: {code}"
                );
            } else {
                assert!(
                    flagged.is_empty(),
                    "import {import_path} should NOT be flagged in: {code}"
                );
            }
        }
    }

    #[test]
    fn test_python_from_import_alias_not_flagged() {
        let module = DeadCodeModule::new();
        let files = vec![make_file(
            "test.py",
            "from os.path import join as pj\n\nx = pj(\"/tmp\", \"f\")\n",
        )];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let flagged: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "unused-import" && f.message.contains("os.path"))
            .collect();
        assert!(
            flagged.is_empty(),
            "from os.path import join as pj should not be flagged when pj is used"
        );
    }
}
