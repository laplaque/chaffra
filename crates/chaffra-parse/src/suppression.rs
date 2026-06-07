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
/// - `code // chaffra:ignore rule` -- inline suppression on the same line
/// - `chaffra:ignore *` -- wildcard, suppress all rules
pub fn scan_suppressions(source: &str, _language: Language) -> Vec<Suppression> {
    let mut suppressions = Vec::new();

    for (idx, line) in source.lines().enumerate() {
        if let Some((rest, text)) = find_suppression_in_line(line) {
            let rules = parse_suppression_rules(rest);
            suppressions.push(Suppression {
                line: idx as u32 + 1,
                rules,
                text,
            });
        }
    }

    suppressions
}

/// Check whether the character at `pos` is inside a string literal.
///
/// Counts unescaped double-quote (and single-quote for Python's `#`) characters
/// before `pos`. If the count is odd, the position is inside a string literal.
fn is_inside_string_literal(line: &str, pos: usize) -> bool {
    let prefix = &line[..pos];
    let mut double_quotes = 0u32;
    let mut single_quotes = 0u32;
    let bytes = prefix.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            // Skip escaped character.
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            double_quotes += 1;
        } else if bytes[i] == b'\'' {
            single_quotes += 1;
        }
        i += 1;
    }
    // Inside a string if either quote count is odd.
    double_quotes % 2 != 0 || single_quotes % 2 != 0
}

fn find_suppression_in_line(line: &str) -> Option<(&str, String)> {
    const MARKER: &str = "chaffra:ignore";

    if let Some(comment_start) = line.find("//") {
        if !is_inside_string_literal(line, comment_start) {
            let comment = &line[comment_start..];
            if let Some(pos) = comment.find(MARKER) {
                let rest = &comment[pos + MARKER.len()..];
                return Some((rest, comment.trim().to_owned()));
            }
        }
    }
    if let Some(comment_start) = line.find('#') {
        if !is_inside_string_literal(line, comment_start) {
            let comment = &line[comment_start..];
            if let Some(pos) = comment.find(MARKER) {
                let rest = &comment[pos + MARKER.len()..];
                return Some((rest, comment.trim().to_owned()));
            }
        }
    }
    None
}

fn parse_suppression_rules(rest: &str) -> Vec<String> {
    let rest = rest.trim();
    if rest.is_empty() || rest == "*" {
        Vec::new()
    } else {
        rest.split(',')
            .map(|r| r.trim().to_owned())
            .filter(|r| !r.is_empty() && r != "*")
            .collect()
    }
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

/// Check if a specific line in source code is suppressed for a given rule.
///
/// This is a convenience function that combines `scan_suppressions` and `is_suppressed`
/// for one-shot checks without pre-scanning.
pub fn is_line_suppressed(source: &str, line_num: u32, rule_id: &str, lang: Language) -> bool {
    let suppressions = scan_suppressions(source, lang);
    is_suppressed(&suppressions, line_num, rule_id)
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

    #[test]
    fn test_inline_suppression_go() {
        let src = "result := fabricated(x) // chaffra:ignore phantom-api-call\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].line, 1);
        assert_eq!(suppressions[0].rules, vec!["phantom-api-call"]);
    }

    #[test]
    fn test_inline_suppression_python() {
        let src = "result = bad_fn(data)  # chaffra:ignore phantom-api-call\n";
        let suppressions = scan_suppressions(src, Language::Python);
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].line, 1);
        assert_eq!(suppressions[0].rules, vec!["phantom-api-call"]);
    }

    #[test]
    fn test_wildcard_star_suppression() {
        let src = "code() // chaffra:ignore *\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert_eq!(suppressions.len(), 1);
        assert!(suppressions[0].rules.is_empty());
    }

    #[test]
    fn test_suppression_in_string_literal_not_matched() {
        // Go: // inside a string literal should not be treated as a comment
        let src = "fmt.Println(\"// chaffra:ignore *\")\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert!(
            suppressions.is_empty(),
            "should not detect suppression inside a string literal"
        );

        // Rust/Go style with let
        let src2 = "let s = \"// chaffra:ignore *\";\n";
        let suppressions2 = scan_suppressions(src2, Language::Go);
        assert!(
            suppressions2.is_empty(),
            "should not detect suppression inside a string literal (let)"
        );
    }

    #[test]
    fn test_suppression_in_python_string_not_matched() {
        // Python: # inside a string literal should not be treated as a comment
        let src = "x = \"# chaffra:ignore rule\"\n";
        let suppressions = scan_suppressions(src, Language::Python);
        assert!(
            suppressions.is_empty(),
            "should not detect suppression inside a Python string literal"
        );

        // Single-quoted Python string
        let src2 = "x = '# chaffra:ignore rule'\n";
        let suppressions2 = scan_suppressions(src2, Language::Python);
        assert!(
            suppressions2.is_empty(),
            "should not detect suppression inside a single-quoted Python string"
        );
    }

    #[test]
    fn test_is_line_suppressed_convenience() {
        let src = "package main\n// chaffra:ignore dead-code\nfunc unused() {}\n";
        assert!(is_line_suppressed(src, 3, "dead-code", Language::Go));
        assert!(!is_line_suppressed(src, 3, "complexity", Language::Go));
        assert!(!is_line_suppressed(src, 1, "dead-code", Language::Go));
    }

    #[test]
    fn test_escaped_quote_does_not_break_string_detection() {
        let src = "x := fmt.Sprintf(\"val=\\\"%s\\\"\" ) // chaffra:ignore dead-code\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert_eq!(suppressions.len(), 1);
    }
}
