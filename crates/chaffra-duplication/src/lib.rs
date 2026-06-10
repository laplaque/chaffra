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

/// A raw clone match: two locations sharing the same normalized token sequence.
#[derive(Debug, Clone)]
struct RawCloneMatch {
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

/// A single occurrence of a clone in a specific file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CloneOccurrence {
    file: String,
    start_line: u32,
    end_line: u32,
}

/// A family of clones sharing the same normalized token structure.
#[derive(Debug, Clone)]
struct CloneFamily {
    family_id: String,
    occurrences: Vec<CloneOccurrence>,
    token_count_min: usize,
    token_count_max: usize,
    similarity: f32,
    raw_pair_count: usize,
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

/// Coalesce overlapping or adjacent line ranges into minimal covering ranges.
fn coalesce_ranges(ranges: &mut [(u32, u32)]) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return vec![];
    }
    ranges.sort();
    let mut result = vec![ranges[0]];
    for &(start, end) in &ranges[1..] {
        let last = result.last_mut().unwrap();
        if start <= last.1 + 1 {
            last.1 = last.1.max(end);
        } else {
            result.push((start, end));
        }
    }
    result
}

/// Compute a deterministic family ID from sorted occurrences.
fn family_id_from_occurrences(occurrences: &[CloneOccurrence]) -> String {
    let mut hasher = Sha256::new();
    for o in occurrences {
        hasher.update(o.file.as_bytes());
        hasher.update(b":");
        hasher.update(o.start_line.to_le_bytes());
        hasher.update(b"-");
        hasher.update(o.end_line.to_le_bytes());
        hasher.update(b"\n");
    }
    let hash = hasher.finalize();
    format!(
        "dup:{:08x}",
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    )
}

/// Coalesce occurrences that share the same file and overlap/adjoin.
fn coalesce_occurrences(mut occs: Vec<CloneOccurrence>) -> Vec<CloneOccurrence> {
    occs.sort();
    if occs.is_empty() {
        return occs;
    }
    let mut result: Vec<CloneOccurrence> = vec![occs[0].clone()];
    for occ in &occs[1..] {
        let last = result.last_mut().unwrap();
        if last.file == occ.file && occ.start_line <= last.end_line + 1 {
            last.end_line = last.end_line.max(occ.end_line);
        } else {
            result.push(occ.clone());
        }
    }
    result
}

/// Merge families whose occurrences overlap in the same file using union-find.
fn merge_overlapping_families(families: &mut Vec<CloneFamily>) {
    let n = families.len();
    if n <= 1 {
        return;
    }
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }

    fn union(parent: &mut [usize], i: usize, j: usize) {
        let pi = find(parent, i);
        let pj = find(parent, j);
        if pi != pj {
            parent[pj] = pi;
        }
    }

    let mut file_index: HashMap<String, Vec<(usize, u32, u32)>> = HashMap::new();
    for (idx, family) in families.iter().enumerate() {
        for occ in &family.occurrences {
            file_index.entry(occ.file.clone()).or_default().push((
                idx,
                occ.start_line,
                occ.end_line,
            ));
        }
    }

    for entries in file_index.values_mut() {
        entries.sort_by(|a, b| a.1.cmp(&b.1).then(a.2.cmp(&b.2)));
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                let (_, _, end_i) = entries[i];
                let (_, start_j, _) = entries[j];
                if start_j > end_i + 1 {
                    break;
                }
                union(&mut parent, entries[i].0, entries[j].0);
            }
        }
    }

    let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }

    if groups.len() == n {
        return;
    }

    let old = std::mem::take(families);
    for (_, indices) in groups {
        let mut merged = old[indices[0]].clone();
        for &idx in &indices[1..] {
            let other = &old[idx];
            merged.raw_pair_count += other.raw_pair_count;
            merged.token_count_min = merged.token_count_min.min(other.token_count_min);
            merged.token_count_max = merged.token_count_max.max(other.token_count_max);
            merged.similarity = merged.similarity.max(other.similarity);
            merged.occurrences.extend(other.occurrences.clone());
        }
        merged.occurrences = coalesce_occurrences(merged.occurrences);
        merged.family_id = family_id_from_occurrences(&merged.occurrences);
        families.push(merged);
    }
}

/// Group raw clone matches by family fingerprint, coalesce overlapping ranges,
/// then merge families whose occurrences overlap in the same file.
fn aggregate_families(raw_matches: Vec<RawCloneMatch>) -> Vec<CloneFamily> {
    if raw_matches.is_empty() {
        return vec![];
    }

    // Pass 1: group by clone-family fingerprint to preserve identity.
    let mut family_map: HashMap<String, Vec<&RawCloneMatch>> = HashMap::new();
    for m in &raw_matches {
        family_map.entry(m.family_id.clone()).or_default().push(m);
    }

    let mut families = Vec::new();
    for (fid, matches) in &family_map {
        let raw_pair_count = matches.len();
        let token_count_min = matches.iter().map(|m| m.token_count).min().unwrap_or(0);
        let token_count_max = matches.iter().map(|m| m.token_count).max().unwrap_or(0);
        let similarity = matches.iter().map(|m| m.similarity).fold(0.0f32, f32::max);

        let mut file_ranges: HashMap<&str, Vec<(u32, u32)>> = HashMap::new();
        for m in matches {
            file_ranges
                .entry(&m.file_a)
                .or_default()
                .push((m.start_a, m.end_a));
            file_ranges
                .entry(&m.file_b)
                .or_default()
                .push((m.start_b, m.end_b));
        }

        let mut occurrences = Vec::new();
        for (file, ranges) in &mut file_ranges {
            for (start, end) in coalesce_ranges(ranges) {
                occurrences.push(CloneOccurrence {
                    file: (*file).to_owned(),
                    start_line: start,
                    end_line: end,
                });
            }
        }
        occurrences.sort();

        families.push(CloneFamily {
            family_id: fid.clone(),
            occurrences,
            token_count_min,
            token_count_max,
            similarity,
            raw_pair_count,
        });
    }

    // Pass 2: merge families whose occurrences overlap in the same file.
    // This collapses adjacent sliding-window families into single families.
    merge_overlapping_families(&mut families);

    families.sort_by(|a, b| a.family_id.cmp(&b.family_id));
    families
}

/// Find clone pairs across all files using sliding window over token sequences.
fn detect_clones(
    file_tokens: &[FileTokens],
    min_tokens: usize,
    mode: NormMode,
) -> Vec<RawCloneMatch> {
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

                clones.push(RawCloneMatch {
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

        let max_families: usize = config
            .get("max-families")
            .and_then(|v| v.parse().ok())
            .unwrap_or(200);

        // Detect raw clone matches.
        let raw_matches = detect_clones(&file_tokens, min_tokens, mode);
        let raw_pair_count = raw_matches.len();

        // Aggregate into families with coalesced ranges.
        let mut families = aggregate_families(raw_matches);
        let total_families = families.len();
        let collapsed_matches: u64 = families
            .iter()
            .map(|f| f.raw_pair_count.saturating_sub(1) as u64)
            .sum();
        let truncated = families.len() > max_families;
        if truncated {
            families.truncate(max_families);
        }

        // Convert families to findings.
        let mut findings = Vec::new();
        for family in &families {
            let primary = &family.occurrences[0];
            let is_function = family.occurrences.iter().any(|o| o.start_line == 1);
            let rule_id = if is_function {
                "duplicate-function"
            } else {
                "duplicate-block"
            };

            let locations_ser: Vec<serde_json::Value> = family
                .occurrences
                .iter()
                .map(|o| {
                    serde_json::json!({
                        "file": o.file,
                        "start": o.start_line,
                        "end": o.end_line,
                    })
                })
                .collect();

            let mut metadata = HashMap::new();
            metadata.insert("family_id".to_owned(), family.family_id.clone());
            metadata.insert("similarity".to_owned(), format!("{:.2}", family.similarity));
            metadata.insert(
                "token_count_min".to_owned(),
                family.token_count_min.to_string(),
            );
            metadata.insert(
                "token_count_max".to_owned(),
                family.token_count_max.to_string(),
            );
            metadata.insert("mode".to_owned(), format!("{mode:?}"));
            metadata.insert(
                "clone_locations".to_owned(),
                serde_json::to_string(&locations_ser).unwrap_or_default(),
            );
            metadata.insert(
                "raw_pair_count".to_owned(),
                family.raw_pair_count.to_string(),
            );
            metadata.insert(
                "reported_location_count".to_owned(),
                family.occurrences.len().to_string(),
            );

            let other_locations: Vec<String> = family
                .occurrences
                .iter()
                .skip(1)
                .map(|o| format!("{}:{}-{}", o.file, o.start_line, o.end_line))
                .collect();
            let others_summary = if other_locations.len() > 3 {
                format!(
                    "{} and {} more",
                    other_locations[..3].join(", "),
                    other_locations.len() - 3
                )
            } else {
                other_locations.join(", ")
            };

            findings.push(Finding {
                rule_id: rule_id.to_owned(),
                message: format!(
                    "clone family ({}-{} tokens, {:.0}% similar, {} locations): {}",
                    family.token_count_min,
                    family.token_count_max,
                    family.similarity * 100.0,
                    family.occurrences.len(),
                    others_summary,
                ),
                severity: Severity::Warning,
                location: Location {
                    file: primary.file.clone(),
                    start_line: primary.start_line,
                    end_line: primary.end_line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: family.similarity,
                actions: vec![],
                metadata,
            });
        }

        let mut counters = HashMap::new();
        counters.insert("raw_clone_pairs".to_owned(), raw_pair_count as u64);
        counters.insert("clone_families".to_owned(), total_families as u64);
        counters.insert("reported_findings".to_owned(), findings.len() as u64);
        counters.insert("collapsed_matches".to_owned(), collapsed_matches);
        if truncated {
            counters.insert(
                "truncated_families".to_owned(),
                (total_families - max_families) as u64,
            );
        }

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
            assert!(f.metadata.contains_key("clone_locations"));
            assert!(f.metadata.contains_key("raw_pair_count"));
            assert!(f.metadata.contains_key("reported_location_count"));
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
        let finding = &result.findings[0];
        assert!(finding.metadata.contains_key("clone_locations"));
        let locations = &finding.metadata["clone_locations"];
        assert!(locations.contains("pkg/a/a.go"));
        assert!(locations.contains("pkg/b/b.go"));
    }

    #[test]
    fn test_overlapping_windows_collapse_into_bounded_families() {
        let module = DuplicationModule::new();
        let block: String = (0..100)
            .map(|i| format!("    x{i} := compute({i})\n"))
            .collect();
        let file_a = format!("package main\n\nfunc A() {{\n{block}}}\n");
        let file_b = format!("package main\n\nfunc B() {{\n{block}}}\n");
        let files = vec![make_file("a.go", &file_a), make_file("b.go", &file_b)];

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "20".to_owned());

        let result = module.analyze(&files, &config).unwrap();

        let raw_pairs = result
            .metrics
            .counters
            .get("raw_clone_pairs")
            .copied()
            .unwrap_or(0);
        let families = result
            .metrics
            .counters
            .get("clone_families")
            .copied()
            .unwrap_or(0);
        let reported = result
            .metrics
            .counters
            .get("reported_findings")
            .copied()
            .unwrap_or(0);

        assert!(
            raw_pairs > reported,
            "raw pairs ({raw_pairs}) should exceed reported findings ({reported}) after coalescing"
        );
        assert!(
            families <= raw_pairs,
            "families ({families}) should be <= raw pairs ({raw_pairs})"
        );
        assert!(
            reported <= 50,
            "100-line identical block with min-tokens=20 should produce far fewer than 100 findings, got {reported}"
        );
    }

    #[test]
    fn test_repeated_blocks_do_not_explode() {
        let module = DuplicationModule::new();
        let block: String = (0..30)
            .map(|i| format!("    line{i} := doWork({i})\n"))
            .collect();
        let mut files = Vec::new();
        for i in 0..10 {
            let content = format!("package p{i}\n\nfunc F{i}() {{\n{block}}}\n");
            files.push(make_file(&format!("pkg{i}/f.go"), &content));
        }

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "15".to_owned());

        let result = module.analyze(&files, &config).unwrap();

        let raw_pairs = result.metrics.counters["raw_clone_pairs"];
        let reported = result.metrics.counters["reported_findings"];

        assert!(
            raw_pairs > 10,
            "10 identical files should produce many raw pairs"
        );
        assert!(
            reported < raw_pairs,
            "reported findings ({reported}) should be far fewer than raw pairs ({raw_pairs})"
        );
    }

    #[test]
    fn test_max_families_cap() {
        let module = DuplicationModule::new();
        let mut files = Vec::new();
        for i in 0..20 {
            let block: String = (0..30)
                .map(|j| format!("    unique{i}_{j} := compute({j})\n"))
                .collect();
            let a = format!("package main\n\nfunc A{i}() {{\n{block}}}\n");
            let b = format!("package main\n\nfunc B{i}() {{\n{block}}}\n");
            files.push(make_file(&format!("a{i}.go"), &a));
            files.push(make_file(&format!("b{i}.go"), &b));
        }

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "15".to_owned());
        config.insert("max-families".to_owned(), "5".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(
            result.findings.len() <= 5,
            "should respect max-families cap, got {}",
            result.findings.len()
        );
        if result
            .metrics
            .counters
            .get("clone_families")
            .copied()
            .unwrap_or(0)
            > 5
        {
            assert!(
                result.metrics.counters.contains_key("truncated_families"),
                "should report truncated_families when capped"
            );
        }
    }

    #[test]
    fn test_coalesce_ranges() {
        let mut ranges = vec![(1, 5), (3, 8), (10, 15), (14, 20), (25, 30)];
        let result = coalesce_ranges(&mut ranges);
        assert_eq!(result, vec![(1, 8), (10, 20), (25, 30)]);
    }

    #[test]
    fn test_coalesce_adjacent_ranges() {
        let mut ranges = vec![(1, 5), (6, 10), (12, 15)];
        let result = coalesce_ranges(&mut ranges);
        assert_eq!(result, vec![(1, 10), (12, 15)]);
    }

    #[test]
    fn test_coalesce_empty() {
        let mut ranges: Vec<(u32, u32)> = vec![];
        let result = coalesce_ranges(&mut ranges);
        assert!(result.is_empty());
    }

    #[test]
    fn test_aggregate_families_groups_by_fingerprint() {
        let matches = vec![
            RawCloneMatch {
                file_a: "a.go".to_owned(),
                start_a: 1,
                end_a: 10,
                file_b: "b.go".to_owned(),
                start_b: 1,
                end_b: 10,
                token_count: 50,
                family_id: "dup:aaaa0001".to_owned(),
                similarity: 1.0,
            },
            RawCloneMatch {
                file_a: "a.go".to_owned(),
                start_a: 2,
                end_a: 11,
                file_b: "b.go".to_owned(),
                start_b: 2,
                end_b: 11,
                token_count: 50,
                family_id: "dup:aaaa0002".to_owned(),
                similarity: 1.0,
            },
            RawCloneMatch {
                file_a: "c.go".to_owned(),
                start_a: 5,
                end_a: 15,
                file_b: "d.go".to_owned(),
                start_b: 5,
                end_b: 15,
                token_count: 50,
                family_id: "dup:bbbb0001".to_owned(),
                similarity: 0.95,
            },
        ];
        let families = aggregate_families(matches);
        // The first two matches overlap in (a.go, b.go) and get merged
        assert_eq!(families.len(), 2, "should produce two families");

        let fam_ab = families
            .iter()
            .find(|f| f.occurrences.iter().any(|o| o.file == "a.go"))
            .unwrap();
        assert_eq!(fam_ab.raw_pair_count, 2);
        assert_eq!(
            fam_ab.occurrences.len(),
            2,
            "two files with coalesced ranges"
        );
        let a_occ = fam_ab
            .occurrences
            .iter()
            .find(|o| o.file == "a.go")
            .unwrap();
        assert_eq!(a_occ.start_line, 1);
        assert_eq!(a_occ.end_line, 11);

        let fam_cd = families
            .iter()
            .find(|f| f.occurrences.iter().any(|o| o.file == "c.go"))
            .unwrap();
        assert_eq!(fam_cd.raw_pair_count, 1);
    }

    #[test]
    fn test_unrelated_blocks_same_file_pair_stay_separate() {
        let module = DuplicationModule::new();
        // Two distinct duplicate blocks between the same pair of files,
        // separated by unique (non-matching) filler to prevent bridging.
        let block_x: String = (0..40)
            .map(|i| format!("    alpha{i} := computeX({i})\n"))
            .collect();
        let block_y: String = (0..40)
            .map(|i| format!("    beta{i} := computeY({i})\n"))
            .collect();
        let filler_a: String = (0..30)
            .map(|i| format!("    onlyInA{i} := separatorA({i})\n"))
            .collect();
        let filler_b: String = (0..30)
            .map(|i| format!("    onlyInB{i} := separatorB({i})\n"))
            .collect();

        let file_a = format!(
            "package main\n\nfunc A1() {{\n{block_x}}}\n\n{filler_a}\nfunc A2() {{\n{block_y}}}\n"
        );
        let file_b = format!(
            "package main\n\nfunc B1() {{\n{block_x}}}\n\n{filler_b}\nfunc B2() {{\n{block_y}}}\n"
        );
        let files = vec![make_file("a.go", &file_a), make_file("b.go", &file_b)];

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "20".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(
            result.findings.len() >= 2,
            "two unrelated blocks between the same files must produce separate families, got {}",
            result.findings.len()
        );
        // Verify the findings reference different line ranges
        let locs: Vec<_> = result
            .findings
            .iter()
            .map(|f| (f.location.start_line, f.location.end_line))
            .collect();
        let all_same = locs.windows(2).all(|w| w[0] == w[1]);
        assert!(
            !all_same,
            "findings should cover different line ranges, got {locs:?}"
        );
    }

    #[test]
    fn test_metrics_report_raw_vs_reported() {
        let module = DuplicationModule::new();
        let block: String = (0..60)
            .map(|i| format!("    x{i} := compute({i})\n"))
            .collect();
        let file_a = format!("package main\n\nfunc A() {{\n{block}}}\n");
        let file_b = format!("package main\n\nfunc B() {{\n{block}}}\n");
        let files = vec![make_file("a.go", &file_a), make_file("b.go", &file_b)];

        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "20".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        assert!(result.metrics.counters.contains_key("raw_clone_pairs"));
        assert!(result.metrics.counters.contains_key("clone_families"));
        assert!(result.metrics.counters.contains_key("reported_findings"));
        assert!(result.metrics.counters.contains_key("collapsed_matches"));
    }
}
