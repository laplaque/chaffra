//! Clone detection with four sensitivity modes.
//!
//! Identifies duplicate code blocks using a token-based suffix-array algorithm.
//! Supports `strict`, `mild`, `weak`, and `semantic` modes so teams can tune how
//! aggressively near-copies and structurally equivalent blocks are reported.

mod tokenizer;

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Location, ModuleInfo, ModuleMetrics, Rule,
    RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokenizer::{NormMode, Token, tokenize};

/// Duplication analysis module.
pub struct DuplicationModule;

impl DuplicationModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DuplicationModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Rules provided by this module.
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "duplicate-block",
        "Duplicate code block",
        "A contiguous block of code is duplicated in another location",
        "duplication",
    ),
    (
        "duplicate-function",
        "Duplicate function",
        "An entire function body is duplicated in another function",
        "duplication",
    ),
];

/// A clone pair: two locations sharing the same normalized token sequence.
#[derive(Debug, Clone)]
struct ClonePair {
    file_a: String,
    start_a: u32,
    end_a: u32,
    file_b: String,
    start_b: u32,
    end_b: u32,
    token_count: usize,
    family_id: String,
    similarity: f32,
}

/// Fingerprint a normalized token sequence into a family ID.
fn family_fingerprint(tokens: &[Token]) -> String {
    let mut hasher = Sha256::new();
    for t in tokens {
        hasher.update(t.text.as_bytes());
        hasher.update(b"\0");
    }
    let hash = hasher.finalize();
    format!(
        "dup:{:08x}",
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    )
}

/// A positioned token sequence from one file.
#[derive(Debug, Clone)]
struct FileTokens {
    file: String,
    tokens: Vec<Token>,
}

/// Find clone pairs across all files using sliding window over token sequences.
fn detect_clones(file_tokens: &[FileTokens], min_tokens: usize, mode: NormMode) -> Vec<ClonePair> {
    let mut clones = Vec::new();

    // Build a map from token-sequence hash -> list of (file_idx, start_pos).
    // We use a sliding window of size `min_tokens`.
    let mut hash_map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();

    for (file_idx, ft) in file_tokens.iter().enumerate() {
        if ft.tokens.len() < min_tokens {
            continue;
        }
        for start in 0..=(ft.tokens.len() - min_tokens) {
            let window = &ft.tokens[start..start + min_tokens];
            let fp = family_fingerprint(window);
            hash_map.entry(fp).or_default().push((file_idx, start));
        }
    }

    // For each hash bucket with >1 entry, emit clone pairs (deduplicated).
    let mut seen: std::collections::HashSet<(usize, usize, usize, usize)> =
        std::collections::HashSet::new();

    for (fp, locations) in &hash_map {
        if locations.len() < 2 {
            continue;
        }
        for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let (fi, si) = locations[i];
                let (fj, sj) = locations[j];

                // Skip overlapping ranges in the same file.
                if fi == fj {
                    let overlap = if si < sj {
                        si + min_tokens > sj
                    } else {
                        sj + min_tokens > si
                    };
                    if overlap {
                        continue;
                    }
                }

                // Deduplicate: ordered pair key.
                let key = if (fi, si) < (fj, sj) {
                    (fi, si, fj, sj)
                } else {
                    (fj, sj, fi, si)
                };
                if !seen.insert(key) {
                    continue;
                }

                // Extend the match beyond min_tokens.
                let tokens_a = &file_tokens[fi].tokens;
                let tokens_b = &file_tokens[fj].tokens;
                let mut len = min_tokens;
                while si + len < tokens_a.len()
                    && sj + len < tokens_b.len()
                    && tokens_a[si + len].text == tokens_b[sj + len].text
                {
                    len += 1;
                }

                let start_line_a = tokens_a[si].line;
                let end_line_a = tokens_a[si + len - 1].line;
                let start_line_b = tokens_b[sj].line;
                let end_line_b = tokens_b[sj + len - 1].line;

                // Calculate similarity based on mode degradation.
                let similarity = match mode {
                    NormMode::Strict => 1.0,
                    NormMode::Mild => 0.95,
                    NormMode::Weak => 0.85,
                    NormMode::Semantic => 0.75,
                };

                clones.push(ClonePair {
                    file_a: file_tokens[fi].file.clone(),
                    start_a: start_line_a,
                    end_a: end_line_a,
                    file_b: file_tokens[fj].file.clone(),
                    start_b: start_line_b,
                    end_b: end_line_b,
                    token_count: len,
                    family_id: fp.clone(),
                    similarity,
                });
            }
        }
    }

    clones
}

/// Detect the language from a file path for tokenization.
fn detect_language(path: &str) -> Option<chaffra_core::diagnostic::Language> {
    let ext = path.rsplit('.').next()?;
    chaffra_core::diagnostic::Language::from_extension(ext)
}

impl AnalysisModule for DuplicationModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "duplication".to_owned(),
            name: "Clone Detection".to_owned(),
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
                    default_severity: Severity::Warning,
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
        let min_tokens: usize = config
            .get("min-tokens")
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);

        let mode_str = config.get("mode").map(|s| s.as_str()).unwrap_or("strict");

        let mode = match mode_str {
            "strict" => NormMode::Strict,
            "mild" => NormMode::Mild,
            "weak" => NormMode::Weak,
            "semantic" => NormMode::Semantic,
            _ => NormMode::Strict,
        };

        // Tokenize all files.
        let mut file_tokens = Vec::new();
        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l) => l,
                None => continue,
            };
            let source = String::from_utf8_lossy(&file.content);
            let tokens = tokenize(&source, lang, mode);
            file_tokens.push(FileTokens {
                file: file.path.clone(),
                tokens,
            });
        }

        // Detect clones.
        let clone_pairs = detect_clones(&file_tokens, min_tokens, mode);

        // Convert to findings.
        let mut findings = Vec::new();
        for pair in &clone_pairs {
            let is_function = pair.start_a == 1 || pair.start_b == 1;
            let rule_id = if is_function {
                "duplicate-function"
            } else {
                "duplicate-block"
            };

            let mut metadata = HashMap::new();
            metadata.insert("family_id".to_owned(), pair.family_id.clone());
            metadata.insert("similarity".to_owned(), format!("{:.2}", pair.similarity));
            metadata.insert("token_count".to_owned(), pair.token_count.to_string());
            metadata.insert("mode".to_owned(), format!("{mode:?}"));
            metadata.insert("other_file".to_owned(), pair.file_b.clone());
            metadata.insert("other_start_line".to_owned(), pair.start_b.to_string());
            metadata.insert("other_end_line".to_owned(), pair.end_b.to_string());

            findings.push(Finding {
                rule_id: rule_id.to_owned(),
                message: format!(
                    "duplicate code block ({} tokens, {:.0}% similar) also found in {}:{}-{}",
                    pair.token_count,
                    pair.similarity * 100.0,
                    pair.file_b,
                    pair.start_b,
                    pair.end_b,
                ),
                severity: Severity::Warning,
                location: Location {
                    file: pair.file_a.clone(),
                    start_line: pair.start_a,
                    end_line: pair.end_a,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: pair.similarity,
                actions: vec![],
                metadata,
            });
        }

        let mut counters = HashMap::new();
        counters.insert("clone_pairs".to_owned(), clone_pairs.len() as u64);

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters,
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "duplicate-block" => Ok(RuleExplanation {
                rule_id: "duplicate-block".to_owned(),
                name: "Duplicate code block".to_owned(),
                description: "Detects contiguous blocks of code that are duplicated across files. \
                    The detection sensitivity depends on the configured mode: strict (exact tokens), \
                    mild (normalize literals), weak (normalize identifiers), or semantic (normalize control flow)."
                    .to_owned(),
                rationale: "Duplicated code increases maintenance cost. When a bug is fixed in one copy, \
                    the other copies may be missed. Extract shared logic into a reusable function or module."
                    .to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore duplicate-block".to_owned(),
                examples: vec![
                    "Two 60-line blocks with identical token sequences in different files".to_owned(),
                ],
            }),
            "duplicate-function" => Ok(RuleExplanation {
                rule_id: "duplicate-function".to_owned(),
                name: "Duplicate function".to_owned(),
                description: "Detects entire function bodies that are duplicated across the codebase. \
                    This is a stronger signal than duplicate-block because the entire function is a clone."
                    .to_owned(),
                rationale: "Duplicate functions should be extracted into a shared utility. \
                    Refactoring requires human judgment about the right abstraction."
                    .to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore duplicate-function".to_owned(),
                examples: vec![
                    "func validate(s string) error { ... } duplicated in two packages".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Duplication requires refactoring -- not auto-fixable.
        Ok(findings
            .iter()
            .map(|f| FixResult {
                rule_id: f.rule_id.clone(),
                applied: false,
                edits: vec![],
                reason: "duplication requires manual refactoring".to_owned(),
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
        let module = DuplicationModule::new();
        let info = module.describe();
        assert_eq!(info.id, "duplication");
        assert_eq!(info.rules.len(), 2);
        assert!(info.languages.contains(&"go".to_owned()));
        assert!(info.languages.contains(&"python".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = DuplicationModule::default();
        assert_eq!(module.describe().id, "duplication");
    }

    #[test]
    fn test_no_duplicates_in_small_files() {
        let module = DuplicationModule::new();
        let files = vec![
            make_file("a.go", "package main\n\nfunc main() {}\n"),
            make_file("b.go", "package main\n\nfunc other() {}\n"),
        ];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(
            result.findings.is_empty(),
            "small distinct files should have no duplicates"
        );
    }

    #[test]
    fn test_detect_identical_blocks() {
        let module = DuplicationModule::new();
        // Create two files with identical large blocks.
        let block: String = (0..60)
            .map(|i| format!("    x{i} := compute({i})\n"))
            .collect();
        let file_a = format!("package main\n\nfunc A() {{\n{block}}}\n");
        let file_b = format!("package main\n\nfunc B() {{\n{block}}}\n");
        let files = vec![make_file("a.go", &file_a), make_file("b.go", &file_b)];

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "20".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "identical large blocks should be detected as duplicates"
        );
        for f in &result.findings {
            assert!(f.rule_id == "duplicate-block" || f.rule_id == "duplicate-function");
            assert!(f.metadata.contains_key("family_id"));
            assert!(f.metadata["family_id"].starts_with("dup:"));
        }
    }

    #[test]
    fn test_modes() {
        let module = DuplicationModule::new();
        // With mild mode, literal normalization should still detect clones.
        let block_a: String = (0..60)
            .map(|i| format!("    x{i} := compute({i})\n"))
            .collect();
        let block_b: String = (0..60)
            .map(|i| format!("    x{i} := compute({i})\n"))
            .collect();
        let file_a = format!("package main\n\nfunc A() {{\n{block_a}}}\n");
        let file_b = format!("package main\n\nfunc B() {{\n{block_b}}}\n");
        let files = vec![make_file("a.go", &file_a), make_file("b.go", &file_b)];

        for mode in &["strict", "mild", "weak", "semantic"] {
            let mut config = HashMap::new();
            config.insert("min-tokens".to_owned(), "20".to_owned());
            config.insert("mode".to_owned(), mode.to_string());
            let result = module.analyze(&files, &config).unwrap();
            assert!(
                !result.findings.is_empty(),
                "mode {mode} should detect identical blocks"
            );
        }
    }

    #[test]
    fn test_explain_duplicate_block() {
        let module = DuplicationModule::new();
        let exp = module.explain("duplicate-block").unwrap();
        assert_eq!(exp.rule_id, "duplicate-block");
        assert!(!exp.description.is_empty());
        assert!(!exp.rationale.is_empty());
    }

    #[test]
    fn test_explain_duplicate_function() {
        let module = DuplicationModule::new();
        let exp = module.explain("duplicate-function").unwrap();
        assert_eq!(exp.rule_id, "duplicate-function");
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = DuplicationModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_fix_not_auto_fixable() {
        let module = DuplicationModule::new();
        let findings = vec![Finding {
            rule_id: "duplicate-block".to_owned(),
            message: "test".to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: "a.go".to_owned(),
                start_line: 1,
                end_line: 10,
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
    fn test_family_fingerprint_deterministic() {
        let tokens = vec![
            Token {
                text: "func".to_owned(),
                line: 1,
            },
            Token {
                text: "main".to_owned(),
                line: 1,
            },
        ];
        let fp1 = family_fingerprint(&tokens);
        let fp2 = family_fingerprint(&tokens);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("dup:"));
    }

    #[test]
    fn test_empty_files() {
        let module = DuplicationModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.metrics.files_analyzed, 0);
    }

    #[test]
    fn test_unsupported_language_ignored() {
        let module = DuplicationModule::new();
        let files = vec![make_file("readme.md", "# Title\nsome content\n")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_python_duplicates() {
        let module = DuplicationModule::new();
        let block: String = (0..60)
            .map(|i| format!("    x{i} = compute({i})\n"))
            .collect();
        let file_a = format!("def func_a():\n{block}");
        let file_b = format!("def func_b():\n{block}");
        let files = vec![make_file("a.py", &file_a), make_file("b.py", &file_b)];

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "20".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should detect Python duplicates"
        );
    }

    #[test]
    fn test_cross_file_detection() {
        let module = DuplicationModule::new();
        let block: String = (0..60)
            .map(|i| format!("    val{i} := process({i})\n"))
            .collect();
        let file_a = format!("package a\n\nfunc A() {{\n{block}}}\n");
        let file_b = format!("package b\n\nfunc B() {{\n{block}}}\n");
        let files = vec![
            make_file("pkg/a/a.go", &file_a),
            make_file("pkg/b/b.go", &file_b),
        ];

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "20".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should detect cross-file duplicates"
        );
        // Verify the finding references the other file.
        let finding = &result.findings[0];
        assert!(finding.metadata.contains_key("other_file"));
    }
}
