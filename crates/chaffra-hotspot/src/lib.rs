//! Hotspot ranking by churn x complexity.
//!
//! Combines git commit history with per-file complexity scores to surface files
//! that are both frequently modified and structurally complex. These hotspots
//! carry the highest maintenance risk and deserve refactoring priority.
//!
//! Hotspot formula: `hotspot_score = commit_count * avg_cyclomatic`

use chaffra_complexity::compute_file_metrics;
use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Per-file hotspot data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotEntry {
    pub file: String,
    pub commit_count: u32,
    pub avg_cyclomatic: f64,
    pub hotspot_score: f64,
}

/// Compute hotspot scores for a set of files and their commit counts.
///
/// `commit_counts` maps file paths to the number of commits touching that file.
/// Files not in the map are assumed to have zero commits.
pub fn compute_hotspots(
    files: &[FileInfo],
    commit_counts: &HashMap<String, u32>,
) -> Result<Vec<HotspotEntry>> {
    let mut entries = Vec::new();

    for file in files {
        let commits = commit_counts.get(&file.path).copied().unwrap_or(0);
        if commits == 0 {
            continue;
        }

        let lang = detect_language(&file.path);
        let avg_cyclomatic = match lang {
            Some(l) if l.has_tree_sitter_grammar() => {
                let metrics = compute_file_metrics(&file.content, l, &file.path)?;
                if metrics.is_empty() {
                    1.0
                } else {
                    metrics.iter().map(|m| m.cyclomatic as f64).sum::<f64>() / metrics.len() as f64
                }
            }
            _ => 1.0, // Default cyclomatic for unsupported languages.
        };

        let hotspot_score = commits as f64 * avg_cyclomatic;
        entries.push(HotspotEntry {
            file: file.path.clone(),
            commit_count: commits,
            avg_cyclomatic,
            hotspot_score,
        });
    }

    // Sort by hotspot score descending.
    entries.sort_by(|a, b| b.hotspot_score.total_cmp(&a.hotspot_score));
    Ok(entries)
}

/// Parse commit counts from a config map.
///
/// The config may contain entries like `commits:<file>=<count>` or a JSON
/// string under the key `commit-counts`.
pub fn parse_commit_counts(config: &HashMap<String, String>) -> HashMap<String, u32> {
    let mut counts = HashMap::new();

    // Try JSON format first.
    if let Some(json_str) = config.get("commit-counts") {
        match serde_json::from_str::<HashMap<String, u32>>(json_str) {
            Ok(parsed) => return parsed,
            Err(e) => eprintln!("warning: failed to parse commit-counts JSON: {e}"),
        }
    }

    // Fall back to individual entries.
    for (key, value) in config {
        if let Some(file) = key.strip_prefix("commits:") {
            if let Ok(count) = value.parse::<u32>() {
                counts.insert(file.to_owned(), count);
            }
        }
    }

    counts
}

fn detect_language(path: &str) -> Option<Language> {
    let ext = path.rsplit('.').next()?;
    Language::from_extension(ext)
}

// ---------------------------------------------------------------------------
// AnalysisModule implementation
// ---------------------------------------------------------------------------

/// Hotspot analysis module.
pub struct HotspotModule;

impl HotspotModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HotspotModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisModule for HotspotModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "hotspot".to_owned(),
            name: "Hotspot Ranking".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec![
                "go".to_owned(),
                "python".to_owned(),
                "php".to_owned(),
                "dart".to_owned(),
                "csharp".to_owned(),
                "rust".to_owned(),
            ],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: vec![
                Rule {
                    id: "hotspot".to_owned(),
                    name: "Hotspot".to_owned(),
                    description:
                        "File has a high churn x complexity score, indicating maintenance risk"
                            .to_owned(),
                    default_severity: Severity::Warning,
                    category: "hotspot".to_owned(),
                },
                Rule {
                    id: "refactoring-target".to_owned(),
                    name: "Refactoring target".to_owned(),
                    description: "File is in the top tier of hotspots and should be refactored"
                        .to_owned(),
                    default_severity: Severity::Error,
                    category: "hotspot".to_owned(),
                },
            ],
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let hotspot_threshold: f64 = config
            .get("hotspot-threshold")
            .and_then(|v| v.parse().ok())
            .unwrap_or(20.0);

        let refactoring_threshold: f64 = config
            .get("refactoring-threshold")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50.0);

        let commit_counts = parse_commit_counts(config);
        let hotspots = compute_hotspots(files, &commit_counts)?;

        let mut findings = Vec::new();

        for entry in &hotspots {
            if entry.hotspot_score >= refactoring_threshold {
                findings.push(Finding {
                    rule_id: "refactoring-target".to_owned(),
                    message: format!(
                        "file `{}` is a refactoring target (score: {:.1}, commits: {}, avg cyclomatic: {:.1})",
                        entry.file, entry.hotspot_score, entry.commit_count, entry.avg_cyclomatic
                    ),
                    severity: Severity::Error,
                    location: Location {
                        file: entry.file.clone(),
                        start_line: 1,
                        end_line: 1,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.9,
                    actions: vec![],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("hotspot_score".to_owned(), format!("{:.1}", entry.hotspot_score));
                        m.insert("commit_count".to_owned(), entry.commit_count.to_string());
                        m.insert("avg_cyclomatic".to_owned(), format!("{:.1}", entry.avg_cyclomatic));
                        m
                    },
                });
            } else if entry.hotspot_score >= hotspot_threshold {
                findings.push(Finding {
                    rule_id: "hotspot".to_owned(),
                    message: format!(
                        "file `{}` is a hotspot (score: {:.1}, commits: {}, avg cyclomatic: {:.1})",
                        entry.file, entry.hotspot_score, entry.commit_count, entry.avg_cyclomatic
                    ),
                    severity: Severity::Warning,
                    location: Location {
                        file: entry.file.clone(),
                        start_line: 1,
                        end_line: 1,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.8,
                    actions: vec![],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert(
                            "hotspot_score".to_owned(),
                            format!("{:.1}", entry.hotspot_score),
                        );
                        m.insert("commit_count".to_owned(), entry.commit_count.to_string());
                        m.insert(
                            "avg_cyclomatic".to_owned(),
                            format!("{:.1}", entry.avg_cyclomatic),
                        );
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
                    c.insert("hotspots_found".to_owned(), hotspots.len() as u64);
                    c
                },
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "hotspot" => Ok(RuleExplanation {
                rule_id: "hotspot".to_owned(),
                name: "Hotspot".to_owned(),
                description: "A file that is both frequently changed and structurally complex. The hotspot score is computed as commit_count * avg_cyclomatic_complexity.".to_owned(),
                rationale: "Hotspots are the most cost-effective refactoring targets because they combine high change frequency (risk of introducing bugs) with high complexity (difficulty of understanding and testing).".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore hotspot".to_owned(),
                examples: vec![
                    "A file with 50 commits and average cyclomatic complexity 4 has a hotspot score of 200.".to_owned(),
                ],
            }),
            "refactoring-target" => Ok(RuleExplanation {
                rule_id: "refactoring-target".to_owned(),
                name: "Refactoring target".to_owned(),
                description: "A file whose hotspot score exceeds the refactoring threshold, indicating it should be split or simplified as a priority.".to_owned(),
                rationale: "Files in the top tier of hotspots represent the highest maintenance cost. Breaking them into smaller, simpler units yields the biggest reduction in bug risk.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore refactoring-target".to_owned(),
                examples: vec![],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Hotspot issues cannot be auto-fixed.
        Ok(vec![])
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

    // --- Hotspot computation ---

    #[test]
    fn test_compute_hotspots_simple() {
        let files = vec![make_file(
            "main.go",
            "package main\n\nfunc main() {\n\tx := 1\n\t_ = x\n}\n",
        )];
        let mut commits = HashMap::new();
        commits.insert("main.go".to_owned(), 10);

        let hotspots = compute_hotspots(&files, &commits).unwrap();
        assert_eq!(hotspots.len(), 1);
        assert_eq!(hotspots[0].file, "main.go");
        assert_eq!(hotspots[0].commit_count, 10);
        assert!(hotspots[0].hotspot_score > 0.0);
    }

    #[test]
    fn test_compute_hotspots_ranking() {
        let files = vec![
            make_file(
                "simple.go",
                "package main\n\nfunc simple() {\n\tx := 1\n\t_ = x\n}\n",
            ),
            make_file(
                "complex.go",
                "package main\n\nfunc complex(x int) int {\n\tif x > 0 {\n\t\tif x > 1 {\n\t\t\treturn x\n\t\t}\n\t\treturn x\n\t}\n\treturn 0\n}\n",
            ),
        ];
        let mut commits = HashMap::new();
        commits.insert("simple.go".to_owned(), 5);
        commits.insert("complex.go".to_owned(), 10);

        let hotspots = compute_hotspots(&files, &commits).unwrap();
        assert_eq!(hotspots.len(), 2);
        // Complex file with more commits should rank first.
        assert_eq!(hotspots[0].file, "complex.go");
        assert!(hotspots[0].hotspot_score > hotspots[1].hotspot_score);
    }

    #[test]
    fn test_compute_hotspots_zero_commits_skipped() {
        let files = vec![make_file("new.go", "package main\n\nfunc f() {}\n")];
        let commits = HashMap::new(); // No commits for this file.

        let hotspots = compute_hotspots(&files, &commits).unwrap();
        assert!(hotspots.is_empty());
    }

    #[test]
    fn test_compute_hotspots_unsupported_language() {
        let files = vec![make_file("main.rs", "fn main() {}")];
        let mut commits = HashMap::new();
        commits.insert("main.rs".to_owned(), 10);

        let hotspots = compute_hotspots(&files, &commits).unwrap();
        assert_eq!(hotspots.len(), 1);
        // Default cyclomatic = 1, so score = 10 * 1 = 10.
        assert!((hotspots[0].hotspot_score - 10.0).abs() < 0.01);
    }

    // --- Commit count parsing ---

    #[test]
    fn test_parse_commit_counts_json() {
        let mut config = HashMap::new();
        config.insert(
            "commit-counts".to_owned(),
            r#"{"main.go": 10, "utils.go": 5}"#.to_owned(),
        );
        let counts = parse_commit_counts(&config);
        assert_eq!(counts.get("main.go"), Some(&10));
        assert_eq!(counts.get("utils.go"), Some(&5));
    }

    #[test]
    fn test_parse_commit_counts_individual() {
        let mut config = HashMap::new();
        config.insert("commits:main.go".to_owned(), "10".to_owned());
        config.insert("commits:utils.go".to_owned(), "5".to_owned());
        let counts = parse_commit_counts(&config);
        assert_eq!(counts.get("main.go"), Some(&10));
        assert_eq!(counts.get("utils.go"), Some(&5));
    }

    #[test]
    fn test_parse_commit_counts_empty() {
        let config = HashMap::new();
        let counts = parse_commit_counts(&config);
        assert!(counts.is_empty());
    }

    // --- Module describe ---

    #[test]
    fn test_describe() {
        let module = HotspotModule::new();
        let info = module.describe();
        assert_eq!(info.id, "hotspot");
        assert_eq!(info.rules.len(), 2);
        let rule_ids: Vec<&str> = info.rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"hotspot"));
        assert!(rule_ids.contains(&"refactoring-target"));
    }

    #[test]
    fn test_default_module() {
        let module = HotspotModule::default();
        assert_eq!(module.describe().id, "hotspot");
    }

    // --- Module explain ---

    #[test]
    fn test_explain_all_rules() {
        let module = HotspotModule::new();
        for rule_id in ["hotspot", "refactoring-target"] {
            let explanation = module.explain(rule_id).unwrap();
            assert_eq!(explanation.rule_id, rule_id);
            assert!(!explanation.description.is_empty());
        }
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = HotspotModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    // --- Module analyze ---

    #[test]
    fn test_analyze_no_commits() {
        let module = HotspotModule::new();
        let files = vec![make_file("main.go", "package main\n\nfunc main() {}\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_produces_hotspot_finding() {
        let module = HotspotModule::new();
        let files = vec![make_file(
            "complex.go",
            "package main\n\nfunc complex(x int) int {\n\tif x > 0 {\n\t\tif x > 1 {\n\t\t\treturn x\n\t\t}\n\t\treturn x\n\t}\n\treturn 0\n}\n",
        )];

        let mut config = HashMap::new();
        config.insert("commits:complex.go".to_owned(), "20".to_owned());
        config.insert("hotspot-threshold".to_owned(), "10".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should find hotspots with high commit count"
        );
    }

    #[test]
    fn test_analyze_produces_refactoring_target() {
        let module = HotspotModule::new();
        let files = vec![make_file(
            "complex.go",
            "package main\n\nfunc complex(x int) int {\n\tif x > 0 {\n\t\tif x > 1 {\n\t\t\treturn x\n\t\t}\n\t\treturn x\n\t}\n\treturn 0\n}\n",
        )];

        let mut config = HashMap::new();
        config.insert("commits:complex.go".to_owned(), "100".to_owned());
        config.insert("refactoring-threshold".to_owned(), "50".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        let refactoring: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "refactoring-target")
            .collect();
        assert!(
            !refactoring.is_empty(),
            "should flag refactoring target for high score"
        );
    }

    // --- Module fix ---

    #[test]
    fn test_fix_returns_empty() {
        let module = HotspotModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    // --- detect_language ---

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("foo.go"), Some(Language::Go));
        assert_eq!(detect_language("bar.py"), Some(Language::Python));
        assert_eq!(detect_language("baz.rs"), Some(Language::Rust));
        assert_eq!(detect_language("app.php"), Some(Language::Php));
        assert_eq!(detect_language("no_ext"), None);
    }
}
