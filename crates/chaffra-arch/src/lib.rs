//! Architecture boundary validation.
//!
//! Enforces import rules derived from architectural presets (layered, hexagonal,
//! feature-sliced, clean) or custom zone/rule definitions from `.chaffra.toml`.
//! Reports violations when a package imports across a declared forbidden boundary.

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::graph::ImportGraph;
use chaffra_parse::parser;
use chaffra_parse::symbols;
use std::collections::HashMap;

/// A zone definition: name + glob patterns mapping files to zones.
#[derive(Debug, Clone)]
pub struct Zone {
    pub name: String,
    pub patterns: Vec<glob::Pattern>,
}

/// A dependency rule between zones.
#[derive(Debug, Clone)]
pub struct DepRule {
    pub from: String,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// Architecture analysis module.
pub struct ArchitectureModule;

impl ArchitectureModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ArchitectureModule {
    fn default() -> Self {
        Self::new()
    }
}

const RULES: &[(&str, &str, &str)] = &[
    (
        "boundary-violation",
        "Boundary violation",
        "An import crosses a declared architectural boundary",
    ),
    (
        "circular-dependency",
        "Circular dependency",
        "A cycle exists in the import graph between files or zones",
    ),
];

impl AnalysisModule for ArchitectureModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "architecture".to_owned(),
            name: "Architecture Boundary Validation".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec![
                "go".to_owned(),
                "python".to_owned(),
                "typescript".to_owned(),
                "javascript".to_owned(),
                "java".to_owned(),
            ],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: Severity::Error,
                    category: "architecture".to_owned(),
                })
                .collect(),
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        // Load zones and rules from config.
        let preset = config.get("preset").map(String::as_str);
        let (zones, dep_rules) = if let Some(preset_name) = preset {
            load_preset(preset_name)
        } else {
            load_config_zones(config)
        };

        // Build the import graph.
        let mut graph = ImportGraph::new();
        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l) => l,
                None => continue,
            };
            let tree = parser::parse(&file.content, lang)?;
            let syms = symbols::extract_symbols(&tree, &file.content, lang, &file.path);
            let imports = symbols::extract_imports(&tree, &file.content, lang);
            let refs = symbols::extract_references(&tree, &file.content, lang, &file.path);
            graph.add_file(&file.path, syms, imports, refs);
        }

        let mut findings = Vec::new();

        // Check boundary violations.
        for node in graph.nodes.values() {
            let from_zone = classify_file(&node.file, &zones);
            if from_zone.is_none() {
                continue;
            }
            let from_zone = from_zone.unwrap();

            for imp in &node.imports {
                // Find which file this import resolves to (best-effort path matching).
                let target_file = resolve_import(&imp.path, &graph);
                if let Some(target_file) = target_file {
                    let to_zone = classify_file(&target_file, &zones);
                    if let Some(to_zone) = to_zone {
                        if from_zone == to_zone {
                            continue;
                        }
                        if is_violation(&from_zone, &to_zone, &dep_rules) {
                            let mut metadata = HashMap::new();
                            metadata.insert("from_zone".to_owned(), from_zone.clone());
                            metadata.insert("to_zone".to_owned(), to_zone.clone());
                            metadata.insert("import_path".to_owned(), imp.path.clone());

                            findings.push(Finding {
                                rule_id: "boundary-violation".to_owned(),
                                message: format!(
                                    "zone `{}` imports from zone `{}` via `{}`, which violates boundary rules",
                                    from_zone, to_zone, imp.path,
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
        }

        // Detect circular dependencies using Tarjan's SCC.
        let cycles = find_cycles(&graph);
        for cycle in &cycles {
            if cycle.len() < 2 {
                continue;
            }
            let cycle_str = cycle.join(" -> ");
            let first_file = &cycle[0];

            let mut metadata = HashMap::new();
            metadata.insert("cycle".to_owned(), cycle_str.clone());
            metadata.insert("cycle_length".to_owned(), cycle.len().to_string());

            findings.push(Finding {
                rule_id: "circular-dependency".to_owned(),
                message: format!(
                    "circular dependency detected: {} -> {}",
                    cycle_str, cycle[0],
                ),
                severity: Severity::Error,
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
                counters: {
                    let mut c = HashMap::new();
                    c.insert("zones".to_owned(), zones.len() as u64);
                    c.insert("cycles".to_owned(), cycles.len() as u64);
                    c
                },
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "boundary-violation" => Ok(RuleExplanation {
                rule_id: "boundary-violation".to_owned(),
                name: "Boundary violation".to_owned(),
                description: "An import from one architectural zone reaches into another zone that is not allowed by the configured dependency rules.".to_owned(),
                rationale: "Maintaining clean boundaries between architectural layers prevents coupling and makes the system easier to change.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore boundary-violation".to_owned(),
                examples: vec![
                    "A handler in the 'presentation' zone importing directly from the 'infrastructure' zone in a layered architecture.".to_owned(),
                ],
            }),
            "circular-dependency" => Ok(RuleExplanation {
                rule_id: "circular-dependency".to_owned(),
                name: "Circular dependency".to_owned(),
                description: "A cycle exists in the import graph: A imports B, B imports C, C imports A.".to_owned(),
                rationale: "Circular dependencies make the build order undefined, complicate testing, and indicate tangled responsibilities.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore circular-dependency".to_owned(),
                examples: vec![
                    "models.go imports utils.go which imports models.go.".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Architecture violations are not auto-fixable.
        Ok(vec![])
    }
}

/// Classify a file into a zone. Returns the first matching zone name.
fn classify_file(file: &str, zones: &[Zone]) -> Option<String> {
    for zone in zones {
        for pattern in &zone.patterns {
            if pattern.matches(file) {
                return Some(zone.name.clone());
            }
        }
    }
    None
}

/// Check if an import from `from_zone` to `to_zone` violates dependency rules.
fn is_violation(from_zone: &str, to_zone: &str, dep_rules: &[DepRule]) -> bool {
    for rule in dep_rules {
        if rule.from == from_zone {
            // If allow list is non-empty, only listed zones are allowed.
            if !rule.allow.is_empty() {
                return !rule.allow.iter().any(|a| a == to_zone);
            }
            // If deny list is non-empty, listed zones are denied.
            if !rule.deny.is_empty() {
                return rule.deny.iter().any(|d| d == to_zone);
            }
        }
    }
    false
}

/// Best-effort import path resolution to a file in the graph.
fn resolve_import(import_path: &str, graph: &ImportGraph) -> Option<String> {
    // Try direct path matching.
    for file in graph.nodes.keys() {
        if file.contains(import_path) || import_path.contains(file) {
            return Some(file.clone());
        }
        // Try matching the last segment.
        let import_base = import_path.rsplit('/').next().unwrap_or(import_path);
        let import_base = import_base.rsplit('.').next().unwrap_or(import_base);
        let file_base = file.rsplit('/').next().unwrap_or(file);
        if file_base.starts_with(import_base) {
            return Some(file.clone());
        }
    }
    None
}

/// Load preset zone definitions and dependency rules.
pub fn load_preset(name: &str) -> (Vec<Zone>, Vec<DepRule>) {
    match name {
        "layered" => preset_layered(),
        "hexagonal" => preset_hexagonal(),
        "feature-sliced" => preset_feature_sliced(),
        "clean" => preset_clean(),
        _ => (Vec::new(), Vec::new()),
    }
}

fn make_zone(name: &str, patterns: &[&str]) -> Zone {
    Zone {
        name: name.to_owned(),
        patterns: patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect(),
    }
}

fn preset_layered() -> (Vec<Zone>, Vec<DepRule>) {
    let zones = vec![
        make_zone(
            "presentation",
            &["**/handler/**", "**/api/**", "**/controller/**"],
        ),
        make_zone(
            "business",
            &["**/service/**", "**/domain/**", "**/usecase/**"],
        ),
        make_zone(
            "data",
            &["**/repo/**", "**/repository/**", "**/store/**", "**/db/**"],
        ),
    ];
    let rules = vec![
        DepRule {
            from: "presentation".to_owned(),
            allow: vec!["business".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "business".to_owned(),
            allow: vec!["data".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "data".to_owned(),
            allow: vec![],
            deny: vec!["presentation".to_owned(), "business".to_owned()],
        },
    ];
    (zones, rules)
}

fn preset_hexagonal() -> (Vec<Zone>, Vec<DepRule>) {
    let zones = vec![
        make_zone("adapter", &["**/adapter/**", "**/adapters/**"]),
        make_zone("port", &["**/port/**", "**/ports/**"]),
        make_zone("core", &["**/core/**", "**/domain/**"]),
    ];
    let rules = vec![
        DepRule {
            from: "adapter".to_owned(),
            allow: vec!["port".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "port".to_owned(),
            allow: vec!["core".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "core".to_owned(),
            allow: vec![],
            deny: vec!["adapter".to_owned(), "port".to_owned()],
        },
    ];
    (zones, rules)
}

fn preset_feature_sliced() -> (Vec<Zone>, Vec<DepRule>) {
    let zones = vec![
        make_zone("app", &["**/app/**"]),
        make_zone("pages", &["**/pages/**"]),
        make_zone("features", &["**/features/**"]),
        make_zone("entities", &["**/entities/**"]),
        make_zone("shared", &["**/shared/**"]),
    ];
    let rules = vec![
        DepRule {
            from: "app".to_owned(),
            allow: vec![
                "pages".to_owned(),
                "features".to_owned(),
                "entities".to_owned(),
                "shared".to_owned(),
            ],
            deny: vec![],
        },
        DepRule {
            from: "pages".to_owned(),
            allow: vec![
                "features".to_owned(),
                "entities".to_owned(),
                "shared".to_owned(),
            ],
            deny: vec![],
        },
        DepRule {
            from: "features".to_owned(),
            allow: vec!["entities".to_owned(), "shared".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "entities".to_owned(),
            allow: vec!["shared".to_owned()],
            deny: vec![],
        },
    ];
    (zones, rules)
}

fn preset_clean() -> (Vec<Zone>, Vec<DepRule>) {
    let zones = vec![
        make_zone(
            "framework",
            &["**/framework/**", "**/infra/**", "**/infrastructure/**"],
        ),
        make_zone(
            "interface",
            &["**/interface/**", "**/controller/**", "**/presenter/**"],
        ),
        make_zone("usecase", &["**/usecase/**", "**/interactor/**"]),
        make_zone(
            "entity",
            &["**/entity/**", "**/entities/**", "**/domain/**"],
        ),
    ];
    let rules = vec![
        DepRule {
            from: "framework".to_owned(),
            allow: vec!["interface".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "interface".to_owned(),
            allow: vec!["usecase".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "usecase".to_owned(),
            allow: vec!["entity".to_owned()],
            deny: vec![],
        },
        DepRule {
            from: "entity".to_owned(),
            allow: vec![],
            deny: vec![
                "framework".to_owned(),
                "interface".to_owned(),
                "usecase".to_owned(),
            ],
        },
    ];
    (zones, rules)
}

/// Load custom zones and rules from module config.
fn load_config_zones(config: &HashMap<String, String>) -> (Vec<Zone>, Vec<DepRule>) {
    // Config keys: zones.NAME=pattern1,pattern2  rules.FROM.allow=ZONE1,ZONE2
    let mut zones = Vec::new();
    let mut dep_rules = Vec::new();

    for (key, value) in config {
        if let Some(zone_name) = key.strip_prefix("zone.") {
            let patterns: Vec<&str> = value.split(',').map(|s| s.trim()).collect();
            zones.push(make_zone(zone_name, &patterns));
        } else if let Some(rest) = key.strip_prefix("rule.") {
            if let Some((from, directive)) = rest.split_once('.') {
                let targets: Vec<String> = value
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                match directive {
                    "allow" => dep_rules.push(DepRule {
                        from: from.to_owned(),
                        allow: targets,
                        deny: vec![],
                    }),
                    "deny" => dep_rules.push(DepRule {
                        from: from.to_owned(),
                        allow: vec![],
                        deny: targets,
                    }),
                    _ => {}
                }
            }
        }
    }

    (zones, dep_rules)
}

/// Mutable state for Tarjan's SCC algorithm.
struct TarjanState {
    adj: Vec<Vec<usize>>,
    index_counter: u32,
    stack: Vec<usize>,
    on_stack: Vec<bool>,
    indices: Vec<u32>,
    lowlinks: Vec<u32>,
    sccs: Vec<Vec<usize>>,
}

impl TarjanState {
    fn new(adj: Vec<Vec<usize>>, n: usize) -> Self {
        Self {
            adj,
            index_counter: 0,
            stack: Vec::new(),
            on_stack: vec![false; n],
            indices: vec![u32::MAX; n],
            lowlinks: vec![0; n],
            sccs: Vec::new(),
        }
    }

    fn strongconnect(&mut self, v: usize) {
        self.indices[v] = self.index_counter;
        self.lowlinks[v] = self.index_counter;
        self.index_counter += 1;
        self.stack.push(v);
        self.on_stack[v] = true;

        for wi in 0..self.adj[v].len() {
            let w = self.adj[v][wi];
            if self.indices[w] == u32::MAX {
                self.strongconnect(w);
                self.lowlinks[v] = self.lowlinks[v].min(self.lowlinks[w]);
            } else if self.on_stack[w] {
                self.lowlinks[v] = self.lowlinks[v].min(self.indices[w]);
            }
        }

        if self.lowlinks[v] == self.indices[v] {
            let mut scc = Vec::new();
            while let Some(w) = self.stack.pop() {
                self.on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            self.sccs.push(scc);
        }
    }
}

/// Find strongly connected components (cycles) using Tarjan's algorithm.
fn find_cycles(graph: &ImportGraph) -> Vec<Vec<String>> {
    let files: Vec<String> = graph.nodes.keys().cloned().collect();
    let file_idx: HashMap<String, usize> = files
        .iter()
        .enumerate()
        .map(|(i, f)| (f.clone(), i))
        .collect();

    // Build adjacency list based on imports.
    let n = files.len();
    let mut adj: Vec<Vec<usize>> = vec![vec![]; n];
    for (file, node) in &graph.nodes {
        let from = file_idx[file];
        for imp in &node.imports {
            if let Some(target) = resolve_import(&imp.path, graph) {
                if let Some(&to) = file_idx.get(&target) {
                    if from != to {
                        adj[from].push(to);
                    }
                }
            }
        }
    }

    let mut state = TarjanState::new(adj, n);
    for i in 0..n {
        if state.indices[i] == u32::MAX {
            state.strongconnect(i);
        }
    }

    // Return only SCCs with more than one node (actual cycles).
    state
        .sccs
        .into_iter()
        .filter(|scc| scc.len() > 1)
        .map(|scc| scc.into_iter().map(|i| files[i].clone()).collect())
        .collect()
}

fn detect_language(path: &str) -> Option<Language> {
    let ext = path.rsplit('.').next()?;
    Language::from_extension(ext)
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
        let module = ArchitectureModule::new();
        let info = module.describe();
        assert_eq!(info.id, "architecture");
        assert_eq!(info.rules.len(), 2);
    }

    #[test]
    fn test_default() {
        let module = ArchitectureModule::default();
        assert_eq!(module.describe().id, "architecture");
    }

    #[test]
    fn test_classify_file() {
        let zones = vec![
            make_zone("presentation", &["handler/**"]),
            make_zone("business", &["service/**"]),
        ];
        assert_eq!(
            classify_file("handler/user.go", &zones),
            Some("presentation".to_owned())
        );
        assert_eq!(
            classify_file("service/auth.go", &zones),
            Some("business".to_owned())
        );
        assert_eq!(classify_file("util/helper.go", &zones), None);
    }

    #[test]
    fn test_is_violation_allow_list() {
        let rules = vec![DepRule {
            from: "presentation".to_owned(),
            allow: vec!["business".to_owned()],
            deny: vec![],
        }];
        assert!(!is_violation("presentation", "business", &rules));
        assert!(is_violation("presentation", "data", &rules));
    }

    #[test]
    fn test_is_violation_deny_list() {
        let rules = vec![DepRule {
            from: "data".to_owned(),
            allow: vec![],
            deny: vec!["presentation".to_owned()],
        }];
        assert!(is_violation("data", "presentation", &rules));
        assert!(!is_violation("data", "business", &rules));
    }

    #[test]
    fn test_no_violation_without_rules() {
        assert!(!is_violation("a", "b", &[]));
    }

    #[test]
    fn test_load_preset_layered() {
        let (zones, rules) = load_preset("layered");
        assert_eq!(zones.len(), 3);
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn test_load_preset_hexagonal() {
        let (zones, rules) = load_preset("hexagonal");
        assert_eq!(zones.len(), 3);
        assert_eq!(rules.len(), 3);
    }

    #[test]
    fn test_load_preset_feature_sliced() {
        let (zones, rules) = load_preset("feature-sliced");
        assert_eq!(zones.len(), 5);
        assert_eq!(rules.len(), 4);
    }

    #[test]
    fn test_load_preset_clean() {
        let (zones, rules) = load_preset("clean");
        assert_eq!(zones.len(), 4);
        assert_eq!(rules.len(), 4);
    }

    #[test]
    fn test_load_preset_unknown() {
        let (zones, rules) = load_preset("nonexistent");
        assert!(zones.is_empty());
        assert!(rules.is_empty());
    }

    #[test]
    fn test_load_config_zones() {
        let mut config = HashMap::new();
        config.insert("zone.web".to_owned(), "web/**".to_owned());
        config.insert("zone.api".to_owned(), "api/**".to_owned());
        config.insert("rule.web.allow".to_owned(), "api".to_owned());

        let (zones, rules) = load_config_zones(&config);
        assert_eq!(zones.len(), 2);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].from, "web");
        assert_eq!(rules[0].allow, vec!["api"]);
    }

    #[test]
    fn test_find_cycles_no_cycle() {
        let mut graph = ImportGraph::new();
        graph.add_file("a.go", vec![], vec![], vec![]);
        graph.add_file("b.go", vec![], vec![], vec![]);
        let cycles = find_cycles(&graph);
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_analyze_empty() {
        let module = ArchitectureModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_explain_boundary_violation() {
        let module = ArchitectureModule::new();
        let explanation = module.explain("boundary-violation").unwrap();
        assert_eq!(explanation.rule_id, "boundary-violation");
        assert!(!explanation.description.is_empty());
        assert!(!explanation.rationale.is_empty());
    }

    #[test]
    fn test_explain_circular_dependency() {
        let module = ArchitectureModule::new();
        let explanation = module.explain("circular-dependency").unwrap();
        assert_eq!(explanation.rule_id, "circular-dependency");
        assert!(!explanation.description.is_empty());
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = ArchitectureModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_fix_returns_empty() {
        let module = ArchitectureModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("foo.go"), Some(Language::Go));
        assert_eq!(detect_language("bar.py"), Some(Language::Python));
        assert_eq!(detect_language("baz.rs"), None);
    }

    #[test]
    fn test_analyze_skips_unsupported() {
        let module = ArchitectureModule::new();
        let files = vec![make_file("test.rs", "fn main() {}")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }
}
