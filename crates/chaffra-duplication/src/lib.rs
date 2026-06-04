//! Clone detection with four sensitivity modes.
//!
//! Identifies duplicate code blocks using a suffix-array algorithm. Supports
//! `strict`, `mild`, `weak`, and `semantic` modes so teams can tune how
//! aggressively near-copies and structurally equivalent blocks are reported.

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Language, Location, ModuleInfo, ModuleMetrics,
    Rule, RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use chaffra_parse::parser;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tree_sitter::Node;

/// Detection mode controlling how aggressively tokens are normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuplicationMode {
    /// Exact token matching (only whitespace/comments stripped).
    Strict,
    /// Normalize string and numeric literals to placeholders.
    Mild,
    /// Normalize all identifiers to a single placeholder.
    Weak,
    /// Normalize control flow keywords to generic tokens.
    Semantic,
}

impl DuplicationMode {
    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "strict" => DuplicationMode::Strict,
            "mild" => DuplicationMode::Mild,
            "weak" => DuplicationMode::Weak,
            "semantic" => DuplicationMode::Semantic,
            _ => DuplicationMode::Mild,
        }
    }
}

/// A single token with its normalized form and source location.
#[derive(Debug, Clone)]
struct Token {
    /// Normalized text of the token.
    normalized: String,
    /// 1-based line in the original source.
    line: u32,
}

/// A detected clone pair.
#[derive(Debug, Clone)]
struct ClonePair {
    file_a: String,
    start_a: u32,
    end_a: u32,
    file_b: String,
    start_b: u32,
    end_b: u32,
    token_count: usize,
    similarity: f32,
    family_id: String,
}

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
const RULES: &[(&str, &str, &str)] = &[
    (
        "duplicate-block",
        "Duplicate code block",
        "A block of code is duplicated in another location",
    ),
    (
        "duplicate-function",
        "Duplicate function",
        "A function body is substantially identical to another function",
    ),
];

impl AnalysisModule for DuplicationModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "duplication".to_owned(),
            name: "Clone Detection".to_owned(),
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
                    default_severity: Severity::Warning,
                    category: "duplication".to_owned(),
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

        let mode = config
            .get("mode")
            .map(|s| DuplicationMode::from_str_loose(s))
            .unwrap_or(DuplicationMode::Mild);

        // Tokenize all files.
        let mut file_tokens: Vec<(String, Vec<Token>)> = Vec::new();
        for file in files {
            let lang = match detect_language(&file.path) {
                Some(l) => l,
                None => continue,
            };
            let tokens = tokenize(&file.content, lang, mode)?;
            if !tokens.is_empty() {
                file_tokens.push((file.path.clone(), tokens));
            }
        }

        // Detect clones using suffix-array approach.
        let clones = detect_clones(&file_tokens, min_tokens);

        let mut findings = Vec::new();
        for clone in &clones {
            let rule_id = if clone.token_count > min_tokens * 2 {
                "duplicate-function"
            } else {
                "duplicate-block"
            };

            let mut metadata = HashMap::new();
            metadata.insert("family_id".to_owned(), clone.family_id.clone());
            metadata.insert("token_count".to_owned(), clone.token_count.to_string());
            metadata.insert(
                "similarity".to_owned(),
                format!("{:.0}%", clone.similarity * 100.0),
            );
            metadata.insert("other_file".to_owned(), clone.file_b.clone());
            metadata.insert("other_start_line".to_owned(), clone.start_b.to_string());
            metadata.insert("other_end_line".to_owned(), clone.end_b.to_string());

            findings.push(Finding {
                rule_id: rule_id.to_owned(),
                message: format!(
                    "duplicate code block ({} tokens, {:.0}% similar) also found in {}:{}-{}",
                    clone.token_count,
                    clone.similarity * 100.0,
                    clone.file_b,
                    clone.start_b,
                    clone.end_b,
                ),
                severity: Severity::Warning,
                location: Location {
                    file: clone.file_a.clone(),
                    start_line: clone.start_a,
                    end_line: clone.end_a,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: clone.similarity,
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
                    c.insert("clone_pairs".to_owned(), clones.len() as u64);
                    c
                },
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "duplicate-block" => Ok(RuleExplanation {
                rule_id: "duplicate-block".to_owned(),
                name: "Duplicate code block".to_owned(),
                description: "A sequence of tokens that appears in two or more locations, exceeding the minimum token threshold.".to_owned(),
                rationale: "Duplicated code increases maintenance burden. When a bug is fixed in one copy, all copies must be updated.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore duplicate-block".to_owned(),
                examples: vec![
                    "Two functions with identical error-handling boilerplate.".to_owned(),
                    "Copy-pasted validation logic across handlers.".to_owned(),
                ],
            }),
            "duplicate-function" => Ok(RuleExplanation {
                rule_id: "duplicate-function".to_owned(),
                name: "Duplicate function".to_owned(),
                description: "Two functions have substantially identical bodies, differing only in names or literals.".to_owned(),
                rationale: "Extract a shared helper or use generics/parameters to eliminate duplication.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore duplicate-function".to_owned(),
                examples: vec![
                    "Two handler functions with identical logic but different route paths.".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Duplication is not auto-fixable.
        Ok(vec![])
    }
}

/// Tokenize source code, stripping comments and whitespace, normalizing per mode.
fn tokenize(source: &[u8], language: Language, mode: DuplicationMode) -> Result<Vec<Token>> {
    let tree = parser::parse(source, language)?;
    let root = tree.root_node();
    let mut tokens = Vec::new();
    collect_tokens(root, source, mode, &mut tokens);
    Ok(tokens)
}

fn collect_tokens(node: Node<'_>, source: &[u8], mode: DuplicationMode, tokens: &mut Vec<Token>) {
    // Skip comment nodes entirely.
    if is_comment_node(node.kind()) {
        return;
    }

    if node.child_count() == 0 {
        // Leaf node -- this is a token.
        let text = node.utf8_text(source).unwrap_or("").to_owned();
        if text.trim().is_empty() {
            return;
        }
        let normalized = normalize_token(&text, node.kind(), mode);
        tokens.push(Token {
            normalized,
            line: node.start_position().row as u32 + 1,
        });
    } else {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            collect_tokens(child, source, mode, tokens);
        }
    }
}

fn is_comment_node(kind: &str) -> bool {
    matches!(kind, "comment" | "line_comment" | "block_comment")
}

fn normalize_token(text: &str, kind: &str, mode: DuplicationMode) -> String {
    match mode {
        DuplicationMode::Strict => text.to_owned(),
        DuplicationMode::Mild => {
            if is_string_literal(kind) {
                "$STR".to_owned()
            } else if is_number_literal(kind) {
                "$NUM".to_owned()
            } else {
                text.to_owned()
            }
        }
        DuplicationMode::Weak => {
            if is_string_literal(kind) {
                "$STR".to_owned()
            } else if is_number_literal(kind) {
                "$NUM".to_owned()
            } else if is_identifier(kind) {
                "$ID".to_owned()
            } else {
                text.to_owned()
            }
        }
        DuplicationMode::Semantic => {
            if is_string_literal(kind) {
                "$STR".to_owned()
            } else if is_number_literal(kind) {
                "$NUM".to_owned()
            } else if is_identifier(kind) {
                "$ID".to_owned()
            } else if is_control_flow(text) {
                "$CF".to_owned()
            } else {
                text.to_owned()
            }
        }
    }
}

fn is_string_literal(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "interpreted_string_literal"
            | "raw_string_literal"
            | "template_string"
            | "string_content"
            | "escape_sequence"
            | "string_fragment"
    )
}

fn is_number_literal(kind: &str) -> bool {
    matches!(
        kind,
        "number"
            | "integer"
            | "int_literal"
            | "float_literal"
            | "decimal_integer_literal"
            | "decimal_floating_point_literal"
    )
}

fn is_identifier(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "type_identifier"
            | "field_identifier"
            | "package_identifier"
            | "property_identifier"
    )
}

fn is_control_flow(text: &str) -> bool {
    matches!(
        text,
        "if" | "else"
            | "for"
            | "while"
            | "switch"
            | "case"
            | "break"
            | "continue"
            | "return"
            | "try"
            | "catch"
            | "finally"
            | "throw"
            | "do"
            | "elif"
            | "except"
            | "raise"
    )
}

/// Compute SHA-256 fingerprint for a normalized token sequence, returning `dup:XXXXXXXX`.
fn fingerprint(tokens: &[Token]) -> String {
    let mut hasher = Sha256::new();
    for tok in tokens {
        hasher.update(tok.normalized.as_bytes());
        hasher.update(b"\x00");
    }
    let hash = hasher.finalize();
    format!(
        "dup:{:08x}",
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    )
}

/// Detect clone pairs across all files using a suffix-array-based approach.
///
/// We build a concatenated token sequence with file boundaries, then find
/// repeated subsequences of length >= min_tokens.
fn detect_clones(file_tokens: &[(String, Vec<Token>)], min_tokens: usize) -> Vec<ClonePair> {
    // Build hash map: hash(window) -> list of (file_idx, token_start_idx).
    let mut hash_map: HashMap<String, Vec<(usize, usize)>> = HashMap::new();

    for (file_idx, (_file, tokens)) in file_tokens.iter().enumerate() {
        if tokens.len() < min_tokens {
            continue;
        }
        for start in 0..=(tokens.len() - min_tokens) {
            let window = &tokens[start..start + min_tokens];
            let fp = fingerprint(window);
            hash_map.entry(fp).or_default().push((file_idx, start));
        }
    }

    let mut clones = Vec::new();
    let mut seen_pairs: HashMap<(usize, usize, usize, usize), bool> = HashMap::new();

    for locations in hash_map.values() {
        if locations.len() < 2 {
            continue;
        }
        for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let (fi, si) = locations[i];
                let (fj, sj) = locations[j];

                // Skip same-file overlapping matches.
                if fi == fj && si.abs_diff(sj) < min_tokens {
                    continue;
                }

                let pair_key = if (fi, si) < (fj, sj) {
                    (fi, si, fj, sj)
                } else {
                    (fj, sj, fi, si)
                };
                if seen_pairs.contains_key(&pair_key) {
                    continue;
                }
                seen_pairs.insert(pair_key, true);

                let tokens_a = &file_tokens[fi].1;
                let tokens_b = &file_tokens[fj].1;

                // Extend the match beyond min_tokens.
                let mut len = min_tokens;
                while si + len < tokens_a.len()
                    && sj + len < tokens_b.len()
                    && tokens_a[si + len].normalized == tokens_b[sj + len].normalized
                {
                    len += 1;
                }

                let window_a = &tokens_a[si..si + len];
                let window_b = &tokens_b[sj..sj + len];

                let family_id = fingerprint(window_a);
                let start_a = window_a.first().map(|t| t.line).unwrap_or(1);
                let end_a = window_a.last().map(|t| t.line).unwrap_or(1);
                let start_b = window_b.first().map(|t| t.line).unwrap_or(1);
                let end_b = window_b.last().map(|t| t.line).unwrap_or(1);

                clones.push(ClonePair {
                    file_a: file_tokens[fi].0.clone(),
                    start_a,
                    end_a,
                    file_b: file_tokens[fj].0.clone(),
                    start_b,
                    end_b,
                    token_count: len,
                    similarity: 1.0,
                    family_id,
                });
            }
        }
    }

    clones
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
        let module = DuplicationModule::new();
        let info = module.describe();
        assert_eq!(info.id, "duplication");
        assert_eq!(info.rules.len(), 2);
    }

    #[test]
    fn test_default() {
        let module = DuplicationModule::default();
        assert_eq!(module.describe().id, "duplication");
    }

    #[test]
    fn test_mode_from_str_loose() {
        let cases = vec![
            ("strict", DuplicationMode::Strict),
            ("Strict", DuplicationMode::Strict),
            ("mild", DuplicationMode::Mild),
            ("weak", DuplicationMode::Weak),
            ("semantic", DuplicationMode::Semantic),
            ("unknown", DuplicationMode::Mild),
        ];
        for (input, expected) in cases {
            assert_eq!(
                DuplicationMode::from_str_loose(input),
                expected,
                "input: {input}"
            );
        }
    }

    #[test]
    fn test_tokenize_go() {
        let src = b"package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n";
        let tokens = tokenize(src, Language::Go, DuplicationMode::Strict).unwrap();
        assert!(!tokens.is_empty());
    }

    #[test]
    fn test_tokenize_mild_normalizes_literals() {
        let src = b"package main\n\nfunc main() {\n\tx := 42\n\ty := \"hello\"\n}\n";
        let tokens = tokenize(src, Language::Go, DuplicationMode::Mild).unwrap();
        assert!(
            tokens.iter().any(|t| t.normalized == "$NUM"),
            "should normalize numbers"
        );
    }

    #[test]
    fn test_tokenize_weak_normalizes_identifiers() {
        let src = b"package main\n\nfunc main() {\n\tx := 42\n}\n";
        let tokens = tokenize(src, Language::Go, DuplicationMode::Weak).unwrap();
        assert!(
            tokens.iter().any(|t| t.normalized == "$ID"),
            "should normalize identifiers"
        );
    }

    #[test]
    fn test_fingerprint_deterministic() {
        let tokens = vec![
            Token {
                normalized: "func".to_owned(),
                line: 1,
            },
            Token {
                normalized: "$ID".to_owned(),
                line: 1,
            },
        ];
        let fp1 = fingerprint(&tokens);
        let fp2 = fingerprint(&tokens);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("dup:"));
        assert_eq!(fp1.len(), 12);
    }

    #[test]
    fn test_fingerprint_differs() {
        let t1 = vec![Token {
            normalized: "a".to_owned(),
            line: 1,
        }];
        let t2 = vec![Token {
            normalized: "b".to_owned(),
            line: 1,
        }];
        assert_ne!(fingerprint(&t1), fingerprint(&t2));
    }

    #[test]
    fn test_detect_identical_blocks() {
        let body = "func process() {\n\tx := getData()\n\tif x != nil {\n\t\tfor _, v := range x {\n\t\t\tfmt.Println(v)\n\t\t\tlog.Debug(v)\n\t\t\thandle(v)\n\t\t\tstore(v)\n\t\t\tvalidate(v)\n\t\t\ttransform(v)\n\t\t\tsend(v)\n\t\t\trecord(v)\n\t\t\tnotify(v)\n\t\t\tcleanup(v)\n\t\t}\n\t}\n}\n";
        let src_a = format!("package a\n\n{body}");
        let src_b = format!("package b\n\n{body}");

        let module = DuplicationModule::new();
        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "10".to_owned());
        config.insert("mode".to_owned(), "strict".to_owned());

        let files = vec![make_file("a.go", &src_a), make_file("b.go", &src_b)];
        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should detect duplicate blocks"
        );
        for finding in &result.findings {
            assert!(finding.metadata.contains_key("family_id"));
            assert!(finding.metadata["family_id"].starts_with("dup:"));
        }
    }

    #[test]
    fn test_no_duplicates_for_different_code() {
        let module = DuplicationModule::new();
        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "10".to_owned());

        let files = vec![
            make_file(
                "a.go",
                "package a\n\nfunc alpha() {\n\tfmt.Println(\"alpha\")\n}\n",
            ),
            make_file(
                "b.go",
                "package b\n\nfunc beta() {\n\tlog.Printf(\"beta\")\n}\n",
            ),
        ];
        let result = module.analyze(&files, &config).unwrap();
        assert!(
            result.findings.is_empty(),
            "different code should not be flagged"
        );
    }

    #[test]
    fn test_analyze_empty_files() {
        let module = DuplicationModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_skips_unsupported_language() {
        let module = DuplicationModule::new();
        let files = vec![make_file("test.rs", "fn main() {}")];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_explain_duplicate_block() {
        let module = DuplicationModule::new();
        let explanation = module.explain("duplicate-block").unwrap();
        assert_eq!(explanation.rule_id, "duplicate-block");
        assert!(!explanation.description.is_empty());
        assert!(!explanation.rationale.is_empty());
        assert!(!explanation.examples.is_empty());
    }

    #[test]
    fn test_explain_duplicate_function() {
        let module = DuplicationModule::new();
        let explanation = module.explain("duplicate-function").unwrap();
        assert_eq!(explanation.rule_id, "duplicate-function");
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = DuplicationModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_fix_returns_empty() {
        let module = DuplicationModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language("foo.go"), Some(Language::Go));
        assert_eq!(detect_language("bar.py"), Some(Language::Python));
        assert_eq!(detect_language("app.js"), Some(Language::JavaScript));
        assert_eq!(detect_language("app.ts"), Some(Language::TypeScript));
        assert_eq!(detect_language("Main.java"), Some(Language::Java));
        assert_eq!(detect_language("baz.rs"), None);
    }

    #[test]
    fn test_is_comment_node() {
        assert!(is_comment_node("comment"));
        assert!(is_comment_node("line_comment"));
        assert!(is_comment_node("block_comment"));
        assert!(!is_comment_node("identifier"));
    }

    #[test]
    fn test_normalize_token_strict() {
        assert_eq!(
            normalize_token("hello", "identifier", DuplicationMode::Strict),
            "hello"
        );
        assert_eq!(
            normalize_token("42", "int_literal", DuplicationMode::Strict),
            "42"
        );
    }

    #[test]
    fn test_normalize_token_mild() {
        assert_eq!(
            normalize_token("hello", "identifier", DuplicationMode::Mild),
            "hello"
        );
        assert_eq!(
            normalize_token("42", "int_literal", DuplicationMode::Mild),
            "$NUM"
        );
        assert_eq!(
            normalize_token("\"hi\"", "string_literal", DuplicationMode::Mild),
            "$STR"
        );
    }

    #[test]
    fn test_normalize_token_weak() {
        assert_eq!(
            normalize_token("hello", "identifier", DuplicationMode::Weak),
            "$ID"
        );
        assert_eq!(
            normalize_token("42", "int_literal", DuplicationMode::Weak),
            "$NUM"
        );
    }

    #[test]
    fn test_normalize_token_semantic() {
        assert_eq!(
            normalize_token("if", "identifier", DuplicationMode::Semantic),
            "$ID"
        );
        assert_eq!(
            normalize_token("for", "for", DuplicationMode::Semantic),
            "$CF"
        );
        assert_eq!(normalize_token("+", "+", DuplicationMode::Semantic), "+");
    }

    #[test]
    fn test_python_duplicate_detection() {
        let body = "def process():\n    data = get_data()\n    if data is not None:\n        for item in data:\n            print(item)\n            log(item)\n            handle(item)\n            store(item)\n            validate(item)\n            transform(item)\n            send(item)\n            record(item)\n";

        let module = DuplicationModule::new();
        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "10".to_owned());

        let files = vec![make_file("a.py", body), make_file("b.py", body)];
        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "should detect duplicate Python blocks"
        );
    }

    #[test]
    fn test_mild_mode_matches_with_different_literals() {
        let src_a = "package a\n\nfunc run() {\n\tx := \"alpha\"\n\tfmt.Println(x)\n\ty := \"bravo\"\n\tfmt.Println(y)\n\tz := \"charlie\"\n\tfmt.Println(z)\n\tw := \"delta\"\n\tfmt.Println(w)\n\tv := \"echo\"\n\tfmt.Println(v)\n}\n";
        let src_b = "package b\n\nfunc run() {\n\tx := \"one\"\n\tfmt.Println(x)\n\ty := \"two\"\n\tfmt.Println(y)\n\tz := \"three\"\n\tfmt.Println(z)\n\tw := \"four\"\n\tfmt.Println(w)\n\tv := \"five\"\n\tfmt.Println(v)\n}\n";

        let module = DuplicationModule::new();
        let mut config = HashMap::new();
        config.insert("min-tokens".to_owned(), "10".to_owned());
        config.insert("mode".to_owned(), "mild".to_owned());

        let files = vec![make_file("a.go", src_a), make_file("b.go", src_b)];
        let result = module.analyze(&files, &config).unwrap();
        assert!(
            !result.findings.is_empty(),
            "mild mode should match blocks with different literals"
        );
    }
}
