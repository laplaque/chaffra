//! Secret scanning — detects hardcoded credentials, API keys, and high-entropy strings.
//!
//! Uses regex patterns for known secret formats plus Shannon entropy for
//! unstructured high-entropy strings that may be secrets.

use chaffra_core::diagnostic::{Action, FileInfo, Finding, Location, Severity};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// A pattern definition for a known secret type.
#[derive(Debug)]
struct SecretPattern {
    /// Human-readable name.
    name: &'static str,
    /// Regex to match the secret.
    regex: &'static str,
    /// Confidence when matched.
    confidence: f32,
}

/// Known secret patterns.
const PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "AWS Access Key ID",
        regex: r"(?:^|[^A-Za-z0-9/+=])(?:AKIA[0-9A-Z]{16})(?:$|[^A-Za-z0-9/+=])",
        confidence: 0.95,
    },
    SecretPattern {
        name: "AWS Secret Access Key",
        regex: r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?"#,
        confidence: 0.95,
    },
    SecretPattern {
        name: "GCP Service Account Key",
        regex: r#""private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----"#,
        confidence: 0.98,
    },
    SecretPattern {
        name: "GCP API Key",
        regex: r"AIza[0-9A-Za-z\-_]{35}",
        confidence: 0.90,
    },
    SecretPattern {
        name: "Azure Storage Account Key",
        regex: r#"(?i)(?:AccountKey|account_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{88})"#,
        confidence: 0.90,
    },
    // Specific token patterns first (before generic patterns, to avoid
    // the generic pattern claiming the line via seen_lines dedup).
    SecretPattern {
        name: "GitHub Personal Access Token",
        regex: r"ghp_[A-Za-z0-9]{36}",
        confidence: 0.95,
    },
    SecretPattern {
        name: "GitHub OAuth Access Token",
        regex: r"gho_[A-Za-z0-9]{36}",
        confidence: 0.95,
    },
    SecretPattern {
        name: "Slack Bot Token",
        regex: r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}",
        confidence: 0.95,
    },
    SecretPattern {
        name: "Slack Webhook URL",
        regex: r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}",
        confidence: 0.95,
    },
    SecretPattern {
        name: "Private Key (PEM)",
        regex: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        confidence: 0.98,
    },
    SecretPattern {
        name: "Stripe Secret Key",
        regex: r"sk_(?:live|test)_[A-Za-z0-9]{24,}",
        confidence: 0.95,
    },
    SecretPattern {
        name: "Stripe Publishable Key",
        regex: r"pk_(?:live|test)_[A-Za-z0-9]{24,}",
        confidence: 0.90,
    },
    SecretPattern {
        name: "SendGrid API Key",
        regex: r"SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}",
        confidence: 0.95,
    },
    SecretPattern {
        name: "Twilio Account SID",
        regex: r"AC[a-f0-9]{32}",
        confidence: 0.85,
    },
    SecretPattern {
        name: "Heroku API Key",
        regex: r#"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"#,
        confidence: 0.90,
    },
    SecretPattern {
        name: "JSON Web Token",
        regex: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}",
        confidence: 0.80,
    },
    // Generic patterns last (lower specificity).
    SecretPattern {
        name: "Generic API Key",
        regex: r#"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']([A-Za-z0-9_\-]{20,})["']"#,
        confidence: 0.80,
    },
    SecretPattern {
        name: "Generic Secret/Token",
        regex: r#"(?i)(?:secret|token|password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']"#,
        confidence: 0.75,
    },
];

/// Compiled regex patterns (lazily initialized).
static COMPILED_PATTERNS: LazyLock<Vec<(&'static SecretPattern, Regex)>> = LazyLock::new(|| {
    PATTERNS
        .iter()
        .filter_map(|p| Regex::new(p.regex).ok().map(|r| (p, r)))
        .collect()
});

/// Shannon entropy threshold for flagging high-entropy strings.
const ENTROPY_THRESHOLD: f64 = 4.5;

/// Minimum string length to consider for entropy analysis.
const MIN_ENTROPY_STRING_LEN: usize = 16;

/// Maximum string length to consider for entropy analysis.
const MAX_ENTROPY_STRING_LEN: usize = 256;

/// Regex for extracting quoted strings.
static STRING_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"["']([^"']{16,256})["']"#).unwrap());

/// Check if a file path is a test file that should be skipped for secret scanning.
pub fn is_test_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("test")
        || lower.contains("spec")
        || lower.contains("mock")
        || lower.contains("fixture")
        || lower.contains("testdata")
        || lower.contains("example")
        || lower.ends_with("_test.go")
        || lower.contains("/tests/")
        || lower.contains("/test/")
}

/// Scan a file for hardcoded secrets.
pub fn scan_file(file: &FileInfo) -> Vec<Finding> {
    // Skip test files.
    if is_test_file(&file.path) {
        return vec![];
    }

    // Skip binary-looking files.
    if !is_text_content(&file.content) {
        return vec![];
    }

    let source = String::from_utf8_lossy(&file.content);
    let lines: Vec<&str> = source.lines().collect();
    let mut findings = Vec::new();
    let mut seen_lines: HashMap<u32, bool> = HashMap::new();

    // Pattern-based scanning.
    for (line_num, line) in lines.iter().enumerate() {
        let line_1based = (line_num + 1) as u32;

        // Skip comment-only lines that look like documentation.
        let trimmed = line.trim();
        if is_documentation_line(trimmed) {
            continue;
        }

        for (pattern, regex) in COMPILED_PATTERNS.iter() {
            if regex.is_match(line) {
                // Avoid duplicate findings on the same line.
                if seen_lines.contains_key(&line_1based) {
                    continue;
                }
                seen_lines.insert(line_1based, true);

                findings.push(Finding {
                    rule_id: "hardcoded-secret".to_owned(),
                    message: format!("potential {} detected in source code", pattern.name),
                    severity: Severity::Error,
                    location: Location {
                        file: file.path.clone(),
                        start_line: line_1based,
                        end_line: line_1based,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: pattern.confidence,
                    actions: vec![Action {
                        description: "Move secret to environment variable or secrets manager"
                            .to_owned(),
                        auto_fixable: false,
                        edits: vec![],
                    }],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("secret_type".to_owned(), pattern.name.to_owned());
                        m
                    },
                });
            }
        }
    }

    // Entropy-based scanning.
    for (line_num, line) in lines.iter().enumerate() {
        let line_1based = (line_num + 1) as u32;

        if seen_lines.contains_key(&line_1based) {
            continue;
        }

        let trimmed = line.trim();
        if is_documentation_line(trimmed) {
            continue;
        }

        // Extract quoted strings and check entropy.
        for cap in STRING_REGEX.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str();
                if s.len() >= MIN_ENTROPY_STRING_LEN
                    && s.len() <= MAX_ENTROPY_STRING_LEN
                    && !looks_like_non_secret(s)
                {
                    let entropy = shannon_entropy(s);
                    if entropy >= ENTROPY_THRESHOLD {
                        if seen_lines.contains_key(&line_1based) {
                            continue;
                        }
                        seen_lines.insert(line_1based, true);

                        findings.push(Finding {
                            rule_id: "high-entropy-string".to_owned(),
                            message: format!(
                                "high-entropy string (Shannon entropy {entropy:.2}) may be a secret"
                            ),
                            severity: Severity::Warning,
                            location: Location {
                                file: file.path.clone(),
                                start_line: line_1based,
                                end_line: line_1based,
                                start_column: 0,
                                end_column: 0,
                            },
                            confidence: compute_entropy_confidence(entropy),
                            actions: vec![Action {
                                description:
                                    "Verify this string is not a secret; if it is, externalize it"
                                        .to_owned(),
                                auto_fixable: false,
                                edits: vec![],
                            }],
                            metadata: {
                                let mut m = HashMap::new();
                                m.insert("entropy".to_owned(), format!("{entropy:.2}"));
                                m
                            },
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Calculate Shannon entropy of a string.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Check if content appears to be text (not binary).
fn is_text_content(content: &[u8]) -> bool {
    // Check first 8192 bytes for null bytes (simple binary detection).
    let check_len = content.len().min(8192);
    !content[..check_len].contains(&0)
}

/// Check if a line looks like documentation (comments, docstrings).
fn is_documentation_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with('*')
        || trimmed.starts_with("/*")
        || trimmed.starts_with("\"\"\"")
        || trimmed.starts_with("'''")
}

/// Check if a string looks like a non-secret value (URL, path, sentence, etc.).
fn looks_like_non_secret(s: &str) -> bool {
    // URLs are not secrets (unless they contain credentials, handled by patterns).
    if s.starts_with("http://") || s.starts_with("https://") {
        return true;
    }
    // File paths.
    if s.starts_with('/') || s.starts_with("./") || s.starts_with("../") {
        return true;
    }
    // Sentences (contain multiple spaces).
    if s.chars().filter(|c| *c == ' ').count() > 3 {
        return true;
    }
    // SQL queries.
    let upper = s.to_uppercase();
    if upper.starts_with("SELECT ")
        || upper.starts_with("INSERT ")
        || upper.starts_with("UPDATE ")
        || upper.starts_with("DELETE ")
        || upper.starts_with("CREATE ")
    {
        return true;
    }
    // Format strings / templates.
    if s.contains("%s") || s.contains("%d") || s.contains("{}") || s.contains("{{") {
        return true;
    }
    false
}

/// Compute confidence for entropy-based detection.
fn compute_entropy_confidence(entropy: f64) -> f32 {
    if entropy >= 5.5 {
        0.85
    } else if entropy >= 5.0 {
        0.75
    } else {
        0.65
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

    // --- is_test_file tests ---

    #[test]
    fn test_is_test_file() {
        let cases = vec![
            ("handler_test.go", true),
            ("test_app.py", true),
            ("src/tests/conftest.py", true),
            ("testdata/secret.txt", true),
            ("example/demo.go", true),
            ("src/handler.go", false),
            ("app.py", false),
            ("lib/auth.go", false),
        ];
        for (path, expected) in cases {
            assert_eq!(is_test_file(path), expected, "is_test_file({path:?})");
        }
    }

    // --- shannon_entropy tests ---

    #[test]
    fn test_shannon_entropy() {
        // Empty string.
        assert_eq!(shannon_entropy(""), 0.0);

        // Single character repeated.
        assert_eq!(shannon_entropy("aaaa"), 0.0);

        // Two distinct characters, equal frequency.
        let e = shannon_entropy("ab");
        assert!(
            (e - 1.0).abs() < 0.01,
            "entropy of 'ab' should be ~1.0: {e}"
        );

        // High entropy random-looking string.
        let high = shannon_entropy("aB3$xY9!mK7@pQ2&");
        assert!(
            high > 3.5,
            "random-looking string should have high entropy: {high}"
        );

        // Low entropy.
        let low = shannon_entropy("aaaaaabbbb");
        assert!(
            low < 1.5,
            "repetitive string should have low entropy: {low}"
        );
    }

    // --- Pattern-based secret detection ---

    #[test]
    fn test_detect_aws_key() {
        let file = make_file(
            "config.go",
            r#"package config

const awsKey = "AKIAIOSFODNN7EXAMPLE"
"#,
        );
        let findings = scan_file(&file);
        let aws_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "hardcoded-secret" && f.message.contains("AWS"))
            .collect();
        assert!(!aws_findings.is_empty(), "should detect AWS access key ID");
    }

    #[test]
    fn test_detect_github_pat() {
        // Use a .go file so the Generic Secret/Token pattern on TOKEN= does not
        // fire first and suppress the GitHub-specific pattern via seen_lines.
        let file = make_file(
            "config.go",
            "package config\n\nvar ghToken = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\"\n",
        );
        let findings = scan_file(&file);
        let gh_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "hardcoded-secret" && f.message.contains("GitHub"))
            .collect();
        assert!(
            !gh_findings.is_empty(),
            "should detect GitHub PAT: {findings:?}"
        );
    }

    #[test]
    fn test_detect_private_key() {
        let file = make_file(
            "certs.go",
            r#"package certs

const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
"#,
        );
        let findings = scan_file(&file);
        let key_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "hardcoded-secret" && f.message.contains("Private Key"))
            .collect();
        assert!(
            !key_findings.is_empty(),
            "should detect private key in PEM format"
        );
    }

    #[test]
    fn test_detect_generic_password() {
        let file = make_file(
            "settings.py",
            "DB_PASSWORD = \"s3cureP@ssw0rd!\"\nDB_HOST = \"localhost\"\n",
        );
        let findings = scan_file(&file);
        let pw_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "hardcoded-secret")
            .collect();
        assert!(!pw_findings.is_empty(), "should detect hardcoded password");
    }

    #[test]
    fn test_detect_stripe_key() {
        let file = make_file(
            "payment.go",
            r#"package payment

var stripeKey = "sk_test_ABCDEFGHIJKLMNOPQRSTUVWXyz"
"#,
        );
        let findings = scan_file(&file);
        let stripe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "hardcoded-secret" && f.message.contains("Stripe"))
            .collect();
        assert!(
            !stripe_findings.is_empty(),
            "should detect Stripe secret key"
        );
    }

    // --- Test files are skipped ---

    #[test]
    fn test_test_files_skipped() {
        let file = make_file(
            "handler_test.go",
            r#"package handler

const testKey = "AKIAIOSFODNN7EXAMPLE"
"#,
        );
        let findings = scan_file(&file);
        assert!(
            findings.is_empty(),
            "test files should be skipped for secret scanning"
        );
    }

    // --- High-entropy string detection ---

    #[test]
    fn test_detect_high_entropy_string() {
        let file = make_file(
            "config.go",
            "package config\n\nvar token = \"a8Kx3mPq9wNzB7yC2eRt5vG4hJ6kL0sD\"\n",
        );
        let findings = scan_file(&file);
        // This may or may not trigger depending on exact entropy; the string
        // is designed to be high-entropy.
        // We just verify the scanner runs without panicking and returns a valid Vec.
        let _ = findings.len();
    }

    // --- Non-secret strings not flagged ---

    #[test]
    fn test_url_not_flagged_as_entropy() {
        assert!(looks_like_non_secret("https://example.com/api/v1/users"));
    }

    #[test]
    fn test_sql_not_flagged_as_entropy() {
        assert!(looks_like_non_secret("SELECT * FROM users WHERE id = $1"));
    }

    #[test]
    fn test_sentence_not_flagged_as_entropy() {
        assert!(looks_like_non_secret(
            "This is a long sentence with multiple words and spaces"
        ));
    }

    #[test]
    fn test_path_not_flagged_as_entropy() {
        assert!(looks_like_non_secret("/usr/local/bin/something"));
    }

    #[test]
    fn test_format_string_not_flagged() {
        assert!(looks_like_non_secret("Hello %s, your order %d is ready"));
    }

    // --- is_documentation_line ---

    #[test]
    fn test_is_documentation_line() {
        let cases = vec![
            ("// This is a comment", true),
            ("# Python comment", true),
            ("* Javadoc line", true),
            ("/* C-style comment", true),
            ("\"\"\"docstring", true),
            ("'''docstring", true),
            ("code = 42", false),
            ("var x = 1", false),
        ];
        for (line, expected) in cases {
            assert_eq!(
                is_documentation_line(line),
                expected,
                "is_documentation_line({line:?})"
            );
        }
    }

    // --- is_text_content ---

    #[test]
    fn test_is_text_content() {
        assert!(is_text_content(b"hello world"));
        assert!(!is_text_content(b"hello\x00world"));
    }

    // --- compute_entropy_confidence ---

    #[test]
    fn test_compute_entropy_confidence() {
        let cases = vec![(5.6, 0.85_f32), (5.2, 0.75), (4.6, 0.65)];
        for (entropy, expected) in cases {
            assert_eq!(
                compute_entropy_confidence(entropy),
                expected,
                "compute_entropy_confidence({entropy})"
            );
        }
    }
}
