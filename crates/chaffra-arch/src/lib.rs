//! Architecture boundary validation.
//!
//! Enforces import rules derived from architectural presets (layered, hexagonal,
//! feature-sliced, clean) or custom zone/rule definitions from `.chaffra.toml`.
//! Reports violations when a package imports across a declared forbidden boundary.
//! Also detects circular dependencies via Tarjan's SCC algorithm.

mod presets;
mod scc;

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::graph::ImportGraph;
use chaffra_parse::parser;
use chaffra_parse::symbols;
use presets::ArchPreset;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Architecture analysis module.
pub struct ArchModule;

impl ArchModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ArchModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Rules provided by this module.
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "boundary-violation",
        "Boundary violation",
        "An import crosses a forbidden architectural boundary",
        "architecture",
    ),
    (
        "circular-dependency",
        "Circular dependency",
        "A group of files form a circular import dependency",
        "architecture",
    ),
];

/// A zone definition: name + glob patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// Zone name (e.g. "domain", "infrastructure", "presentation").
    pub name: String,
    /// Glob patterns that map files to this zone.
    pub patterns: Vec<String>,
}

/// A dependency rule between zones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyRule {
    /// Source zone.
    pub from: String,
    /// Target zone.
    pub to: String,
    /// Whether this dependency is allowed.
    pub allow: bool,
}

/// Architecture configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchConfig {
    /// Zone definitions.
    pub zones: Vec<Zone>,
    /// Dependency rules.
    pub rules: Vec<DependencyRule>,
}

impl ArchConfig {
    /// Create config from a named preset.
    pub fn from_preset(name: &str) -> Option<Self> {
        ArchPreset::from_name(name).map(|p| p.to_config())
    }

    /// Parse zone/rule config from module config map.
    pub fn from_config_map(config: &HashMap<String, String>) -> Option<Self> {
        // Check for preset first.
        if let Some(preset_name) = config.get("preset") {
            return Self::from_preset(preset_name);
        }

        // Parse zones from "zone.<name>" = "<pattern1>,<pattern2>" format.
        let mut zones = Vec::new();
        let mut rules = Vec::new();

        for (key, value) in config {
            if let Some(zone_name) = key.strip_prefix("zone.") {
                let patterns: Vec<String> = value.split(',').map(|s| s.trim().to_owned()).collect();
                zones.push(Zone {
                    name: zone_name.to_owned(),
                    patterns,
                });
            } else if let Some(rule_spec) = key.strip_prefix("deny.") {
                // deny.from -> to
                if let Some((from, to)) = rule_spec.split_once('.') {
                    let _ = value; // deny rules don't need a value
                    rules.push(DependencyRule {
                        from: from.to_owned(),
                        to: to.to_owned(),
                        allow: false,
                    });
                }
            } else if let Some(rule_spec) = key.strip_prefix("allow.") {
                if let Some((from, to)) = rule_spec.split_once('.') {
                    let _ = value;
                    rules.push(DependencyRule {
                        from: from.to_owned(),
                        to: to.to_owned(),
                        allow: true,
                    });
                }
            }
        }

        if zones.is_empty() {
            None
        } else {
            Some(ArchConfig { zones, rules })
        }
    }
}

/// Match a file path against glob patterns.
fn matches_glob(path: &str, pattern: &str) -> bool {
    glob::Pattern::new(pattern)
        .map(|p| p.matches(path))
        .unwrap_or(false)
}

/// Determine which zone a file belongs to.
fn file_zone(path: &str, zones: &[Zone]) -> Option<String> {
    for zone in zones {
        for pattern in &zone.patterns {
            if matches_glob(path, pattern) {
                return Some(zone.name.clone());
            }
        }
    }
    None
}

/// Check if a dependency from `from_zone` to `to_zone` is allowed.
fn is_dependency_allowed(from_zone: &str, to_zone: &str, rules: &[DependencyRule]) -> bool {
    // If there are explicit deny rules, check them.
    for rule in rules {
        if rule.from == from_zone && rule.to == to_zone {
            return rule.allow;
        }
        // Wildcard: deny.X.* means X cannot depend on anything.
        if rule.from == from_zone && rule.to == "*" {
            return rule.allow;
        }
    }
    // Default: allow if no explicit deny rule.
    true
}

/// Detect the language from a file path.
fn detect_language(path: &str) -> Option<Language> {
    let ext = path.rsplit('.').next()?;
    Language::from_extension(ext)
}

impl AnalysisModule for ArchModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "architecture".to_owned(),
            name: "Architecture Validation".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec![
                "go".to_owned(),
                "python".to_owned(),
                "javascript".to_owned(),
                "typescript".to_owned(),
                "java".to_owned(),
            ],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: Severity::Error,
                    category: (*cat).to_owned(),
                })
                .collect(),
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let arch_config = ArchConfig::from_config_map(config)
            .or_else(|| ArchConfig::from_preset("layered"))
            .unwrap();

        // Build import graph.
        let mut graph = ImportGraph::new();
        let mut file_languages: HashMap<String, Language> = HashMap::new();

        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l) if l.has_tree_sitter_grammar() => l,
                _ => continue,
            };
            file_languages.insert(file.path.clone(), lang);

            let tree = match parser::parse(&file.content, lang) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let syms = symbols::extract_symbols(&tree, &file.content, lang, &file.path);
            let imports = symbols::extract_imports(&tree, &file.content, lang);
            let refs = symbols::extract_references(&tree, &file.content, lang, &file.path);
            graph.add_file(&file.path, syms, imports, refs);
        }

        let mut findings = Vec::new();

        // Check boundary violations.
        for node in graph.nodes.values() {
            let from_zone = match file_zone(&node.file, &arch_config.zones) {
                Some(z) => z,
                None => continue,
            };

            for imp in &node.imports {
                // Try to find the target file in the graph.
                for target_node in graph.nodes.values() {
                    if target_node.file == node.file {
                        continue;
                    }
                    // Match import path to target file.
                    let target_matches = target_node.file.contains(&imp.path)
                        || imp.path.contains(
                            target_node
                                .file
                                .trim_end_matches(".go")
                                .trim_end_matches(".py")
                                .trim_end_matches(".js")
                                .trim_end_matches(".ts")
                                .trim_end_matches(".java"),
                        );

                    if !target_matches {
                        continue;
                    }

                    let to_zone = match file_zone(&target_node.file, &arch_config.zones) {
                        Some(z) => z,
                        None => continue,
                    };

                    if from_zone == to_zone {
                        continue;
                    }

                    if !is_dependency_allowed(&from_zone, &to_zone, &arch_config.rules) {
                        let mut metadata = HashMap::new();
                        metadata.insert("from_zone".to_owned(), from_zone.clone());
                        metadata.insert("to_zone".to_owned(), to_zone.clone());
                        metadata.insert("import_path".to_owned(), imp.path.clone());

                        findings.push(Finding {
                            rule_id: "boundary-violation".to_owned(),
                            message: format!(
                                "zone `{from_zone}` imports from zone `{to_zone}` via `{}` (forbidden by architecture rules)",
                                imp.path
                            ),
                            severity: Severity::Error,
                            location: Location {
                                file: node.file.clone(),
                                start_line: imp.line,
                                end_line: imp.line,
                                start_column: 0,
                                end_column: 0,
                            },
                            confidence: 1.0,
                            actions: vec![],
                            metadata,
                        });
                    }
                }
            }
        }

        // Detect circular dependencies using Tarjan's SCC.
        let adjacency = scc::build_adjacency(&graph);
        let cycles = scc::tarjan_scc(&adjacency);

        for cycle in &cycles {
            if cycle.len() < 2 {
                continue;
            }

            let cycle_files: Vec<&str> = cycle.iter().map(|s| s.as_str()).collect();
            let cycle_str = cycle_files.join(" -> ");

            let mut metadata = HashMap::new();
            metadata.insert("cycle_length".to_owned(), cycle.len().to_string());
            metadata.insert("cycle_files".to_owned(), cycle_str.clone());

            // Report on the first file in the cycle.
            let first_file = &cycle[0];
            findings.push(Finding {
                rule_id: "circular-dependency".to_owned(),
                message: format!(
                    "circular dependency detected ({} files): {}",
                    cycle.len(),
                    cycle_str,
                ),
                severity: Severity::Warning,
                location: Location {
                    file: first_file.clone(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata,
            });
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: HashMap::new(),
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "boundary-violation" => Ok(RuleExplanation {
                rule_id: "boundary-violation".to_owned(),
                name: "Boundary violation".to_owned(),
                description: "Detects when code in one architectural zone imports from a forbidden zone. \
                    Zones are defined by file glob patterns, and dependency rules specify which \
                    cross-zone imports are allowed or denied. Four built-in presets are available: \
                    layered, hexagonal, feature-sliced, and clean architecture."
                    .to_owned(),
                rationale: "Architecture boundaries prevent high-level modules from depending on \
                    low-level implementation details, maintaining a clean dependency direction."
                    .to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore boundary-violation".to_owned(),
                examples: vec![
                    "domain/user.go imports from infrastructure/db.go (layered: domain cannot import infrastructure)".to_owned(),
                ],
            }),
            "circular-dependency" => Ok(RuleExplanation {
                rule_id: "circular-dependency".to_owned(),
                name: "Circular dependency".to_owned(),
                description: "Detects groups of files that form a circular import chain using \
                    Tarjan's strongly connected components algorithm. A cycle means A imports B, \
                    B imports C, and C imports A (or any similar chain)."
                    .to_owned(),
                rationale: "Circular dependencies make code harder to understand, test, and \
                    refactor. They prevent clean module boundaries and can cause initialization \
                    ordering issues."
                    .to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore circular-dependency".to_owned(),
                examples: vec![
                    "pkg/a/a.go -> pkg/b/b.go -> pkg/c/c.go -> pkg/a/a.go".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Architecture violations require manual refactoring.
        Ok(findings
            .iter()
            .map(|f| FixResult {
                rule_id: f.rule_id.clone(),
                applied: false,
                edits: vec![],
                reason: "architecture violations require manual refactoring".to_owned(),
            })
            .collect())
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
        let module = ArchModule::new();
        let info = module.describe();
        assert_eq!(info.id, "architecture");
        assert_eq!(info.rules.len(), 2);
        assert!(info.languages.contains(&"go".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = ArchModule::default();
        assert_eq!(module.describe().id, "architecture");
    }

    #[test]
    fn test_file_zone_matching() {
        let zones = vec![
            Zone {
                name: "domain".to_owned(),
                patterns: vec!["domain/**".to_owned()],
            },
            Zone {
                name: "infra".to_owned(),
                patterns: vec!["infrastructure/**".to_owned()],
            },
        ];
        assert_eq!(
            file_zone("domain/user.go", &zones),
            Some("domain".to_owned())
        );
        assert_eq!(
            file_zone("infrastructure/db.go", &zones),
            Some("infra".to_owned())
        );
        assert_eq!(file_zone("other/file.go", &zones), None);
    }

    #[test]
    fn test_dependency_allowed() {
        let rules = vec![DependencyRule {
            from: "domain".to_owned(),
            to: "infra".to_owned(),
            allow: false,
        }];
        assert!(!is_dependency_allowed("domain", "infra", &rules));
        assert!(is_dependency_allowed("infra", "domain", &rules));
        assert!(is_dependency_allowed("domain", "application", &rules));
    }

    #[test]
    fn test_preset_layered() {
        let config = ArchConfig::from_preset("layered");
        assert!(config.is_some());
        let config = config.unwrap();
        assert!(!config.zones.is_empty());
        assert!(!config.rules.is_empty());
    }

    #[test]
    fn test_preset_hexagonal() {
        let config = ArchConfig::from_preset("hexagonal");
        assert!(config.is_some());
    }

    #[test]
    fn test_preset_feature_sliced() {
        let config = ArchConfig::from_preset("feature-sliced");
        assert!(config.is_some());
    }

    #[test]
    fn test_preset_clean() {
        let config = ArchConfig::from_preset("clean");
        assert!(config.is_some());
    }

    #[test]
    fn test_preset_unknown() {
        assert!(ArchConfig::from_preset("nonexistent").is_none());
    }

    #[test]
    fn test_config_from_map_preset() {
        let mut config = HashMap::new();
        config.insert("preset".to_owned(), "layered".to_owned());
        let arch = ArchConfig::from_config_map(&config);
        assert!(arch.is_some());
    }

    #[test]
    fn test_config_from_map_custom_zones() {
        let mut config = HashMap::new();
        config.insert("zone.domain".to_owned(), "src/domain/**".to_owned());
        config.insert("zone.infra".to_owned(), "src/infra/**".to_owned());
        config.insert("deny.domain.infra".to_owned(), "true".to_owned());
        let arch = ArchConfig::from_config_map(&config);
        assert!(arch.is_some());
        let arch = arch.unwrap();
        assert_eq!(arch.zones.len(), 2);
        assert_eq!(arch.rules.len(), 1);
    }

    #[test]
    fn test_empty_files() {
        let module = ArchModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_explain_boundary_violation() {
        let module = ArchModule::new();
        let exp = module.explain("boundary-violation").unwrap();
        assert_eq!(exp.rule_id, "boundary-violation");
        assert!(!exp.description.is_empty());
        assert_eq!(exp.default_severity, Severity::Error);
    }

    #[test]
    fn test_explain_circular_dependency() {
        let module = ArchModule::new();
        let exp = module.explain("circular-dependency").unwrap();
        assert_eq!(exp.rule_id, "circular-dependency");
        assert!(!exp.description.is_empty());
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = ArchModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_fix_not_auto_fixable() {
        let module = ArchModule::new();
        let findings = vec![Finding {
            rule_id: "boundary-violation".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Error,
            location: Location {
                file: "a.go".to_owned(),
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
        assert!(results[0].reason.contains("manual refactoring"));
    }

    #[test]
    fn test_no_violations_in_same_zone() {
        let module = ArchModule::new();
        let files = vec![
            make_file(
                "domain/user.go",
                "package domain\n\nimport \"domain/types\"\n\nfunc GetUser() {}\n",
            ),
            make_file("domain/types.go", "package domain\n\ntype User struct{}\n"),
        ];
        let mut config = HashMap::new();
        config.insert("preset".to_owned(), "layered".to_owned());
        let result = module.analyze(&files, &config).unwrap();
        let boundary_violations: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "boundary-violation")
            .collect();
        assert!(
            boundary_violations.is_empty(),
            "same-zone imports should not be flagged"
        );
    }

    #[test]
    fn test_circular_dependency_detection() {
        // This test verifies the SCC algorithm works on a simple graph.
        let adjacency: HashMap<String, Vec<String>> = HashMap::from([
            ("a.go".to_owned(), vec!["b.go".to_owned()]),
            ("b.go".to_owned(), vec!["c.go".to_owned()]),
            ("c.go".to_owned(), vec!["a.go".to_owned()]),
        ]);
        let sccs = scc::tarjan_scc(&adjacency);
        let multi_sccs: Vec<_> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert!(
            !multi_sccs.is_empty(),
            "should detect the cycle a -> b -> c -> a"
        );
    }

    #[test]
    fn test_no_cycles_in_dag() {
        let adjacency: HashMap<String, Vec<String>> = HashMap::from([
            ("a.go".to_owned(), vec!["b.go".to_owned()]),
            ("b.go".to_owned(), vec!["c.go".to_owned()]),
            ("c.go".to_owned(), vec![]),
        ]);
        let sccs = scc::tarjan_scc(&adjacency);
        let multi_sccs: Vec<_> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert!(multi_sccs.is_empty(), "DAG should have no cycles");
    }

    #[test]
    fn test_glob_matching() {
        assert!(matches_glob("domain/user.go", "domain/**"));
        assert!(matches_glob("infrastructure/db.go", "infrastructure/**"));
        assert!(!matches_glob("other/file.go", "domain/**"));
    }

    #[test]
    fn test_layered_denies_presentation_to_infrastructure() {
        let config = ArchConfig::from_preset("layered").unwrap();
        assert!(
            !is_dependency_allowed("presentation", "infrastructure", &config.rules),
            "layered preset must deny presentation -> infrastructure"
        );
    }

    #[test]
    fn test_layered_fixture_catches_boundary_violation() {
        let module = ArchModule::new();
        let files = vec![
            make_file(
                "presentation/handler.go",
                "package presentation\n\nimport \"infrastructure\"\n\ntype Handler struct{}\n",
            ),
            make_file(
                "infrastructure/repo.go",
                "package infrastructure\n\nimport \"domain\"\n\ntype UserRepo struct{}\n",
            ),
            make_file(
                "domain/user.go",
                "package domain\n\ntype User struct {\n\tID int\n\tName string\n}\n",
            ),
        ];
        let mut config = HashMap::new();
        config.insert("preset".to_owned(), "layered".to_owned());
        let result = module.analyze(&files, &config).unwrap();
        let violations: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "boundary-violation")
            .collect();
        assert!(
            !violations.is_empty(),
            "layered preset must flag presentation importing from infrastructure"
        );
        assert!(
            violations
                .iter()
                .any(|f| f.location.file == "presentation/handler.go")
        );
    }

    #[test]
    fn test_layered_allows_valid_dependencies() {
        let config = ArchConfig::from_preset("layered").unwrap();
        assert!(is_dependency_allowed(
            "presentation",
            "application",
            &config.rules
        ));
        assert!(is_dependency_allowed(
            "application",
            "domain",
            &config.rules
        ));
        assert!(is_dependency_allowed(
            "infrastructure",
            "domain",
            &config.rules
        ));
    }
}
