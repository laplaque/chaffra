//! Suppression comment scanning for `// chaffra:ignore` and `# chaffra:ignore`.

use chaffra_core::diagnostic::Language;

/// A suppression comment found in source code.
#[derive(Debug, Clone, PartialEq)]
pub struct Suppression {
    /// 1-based line number where the suppression comment appears.
    pub line: u32,
    /// Optional rule IDs to suppress (empty means suppress all).
    pub rules: Vec<String>,
    /// The raw comment text.
    pub text: String,
}

/// Scan source code for suppression comments.
///
/// Recognizes both Go-style (`// chaffra:ignore`) and Python-style
/// (`# chaffra:ignore`) comments, with optional rule IDs:
/// - `// chaffra:ignore` -- suppress all rules on the next line
/// - `// chaffra:ignore unused-function,unused-type` -- suppress specific rules
pub fn scan_suppressions(source: &str, _language: Language) -> Vec<Suppression> {
    let mut suppressions = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        // Check for Go-style: // chaffra:ignore
        // Check for Python-style: # chaffra:ignore
        let rest = trimmed
            .strip_prefix("// chaffra:ignore")
            .or_else(|| trimmed.strip_prefix("# chaffra:ignore"));

        if let Some(rest) = rest {
            let rules: Vec<String> = if rest.is_empty() {
                Vec::new()
            } else {
                rest.trim()
                    .split(',')
                    .map(|r| r.trim().to_owned())
                    .filter(|r| !r.is_empty())
                    .collect()
            };

            suppressions.push(Suppression {
                line: idx as u32 + 1,
                rules,
                text: trimmed.to_owned(),
            });
        }
    }

    suppressions
}

/// Check if a given line is suppressed for a specific rule.
pub fn is_suppressed(suppressions: &[Suppression], line: u32, rule_id: &str) -> bool {
    for s in suppressions {
        // Suppression applies to the next line
        if (s.line == line || s.line + 1 == line)
            && (s.rules.is_empty() || s.rules.iter().any(|r| r == rule_id))
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_go_suppression() {
        let src = "package main\n// chaffra:ignore\nfunc unused() {}\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].line, 2);
        assert!(suppressions[0].rules.is_empty());
    }

    #[test]
    fn test_scan_python_suppression() {
        let src = "# chaffra:ignore unused-function\ndef unused():\n    pass\n";
        let suppressions = scan_suppressions(src, Language::Python);
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rules, vec!["unused-function"]);
    }

    #[test]
    fn test_scan_multiple_rules() {
        let src = "// chaffra:ignore unused-function, unused-type\nfunc foo() {}\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert_eq!(suppressions[0].rules.len(), 2);
    }

    #[test]
    fn test_is_suppressed() {
        let suppressions = vec![Suppression {
            line: 2,
            rules: vec!["unused-function".to_owned()],
            text: "// chaffra:ignore unused-function".to_owned(),
        }];
        assert!(is_suppressed(&suppressions, 3, "unused-function"));
        assert!(!is_suppressed(&suppressions, 3, "unused-type"));
        assert!(!is_suppressed(&suppressions, 5, "unused-function"));
    }

    #[test]
    fn test_wildcard_suppression() {
        let suppressions = vec![Suppression {
            line: 2,
            rules: vec![],
            text: "// chaffra:ignore".to_owned(),
        }];
        assert!(is_suppressed(&suppressions, 3, "unused-function"));
        assert!(is_suppressed(&suppressions, 3, "anything"));
    }

    #[test]
    fn test_no_false_positives() {
        let src = "// This is a regular comment\n// chaffra-tool is great\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert!(suppressions.is_empty());
    }
}
