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
pub fn scan_suppressions(source: &str, language: Language) -> Vec<Suppression> {
    let mut suppressions = Vec::new();
    let mut in_multiline_string = false;

    for (idx, line) in source.lines().enumerate() {
        let was_inside = in_multiline_string;
        in_multiline_string = update_multiline_state(line, language, in_multiline_string);

        if was_inside {
            continue;
        }

        if let Some((rest, text)) = find_suppression_in_line(line, language) {
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

/// Update multiline string state after processing a line.
///
/// For slash-comment languages (Go, etc.): tracks backtick raw strings.
/// For hash-comment languages (Python): tracks triple-quoted strings (`"""` and `'''`).
///
/// Returns `true` if we are inside a multiline string after this line.
fn update_multiline_state(line: &str, language: Language, currently_inside: bool) -> bool {
    if uses_slash_comments(language) {
        update_multiline_state_backtick(line, currently_inside)
    } else if uses_hash_comments(language) {
        update_multiline_state_triple_quote(line, currently_inside)
    } else {
        currently_inside
    }
}

/// Count backticks not inside double-quoted strings on this line.
/// Each such backtick toggles the raw string state.
fn update_multiline_state_backtick(line: &str, currently_inside: bool) -> bool {
    let bytes = line.as_bytes();
    let mut in_double_quote = false;
    let mut backtick_count: u32 = 0;
    let mut i = 0;

    while i < bytes.len() {
        if !currently_inside && !in_double_quote && bytes[i] == b'\\' {
            // Skip escaped character (only relevant outside raw strings)
            i += 2;
            continue;
        }
        if !currently_inside || backtick_count % 2 != 0 {
            // We're outside a raw string (or re-entered normal code on this line)
            if bytes[i] == b'"' && !currently_inside {
                in_double_quote = !in_double_quote;
            } else if bytes[i] == b'`' && !in_double_quote {
                backtick_count += 1;
            }
        } else {
            // We're inside a raw string — only backtick matters
            if bytes[i] == b'`' {
                backtick_count += 1;
            }
        }
        i += 1;
    }

    // Odd number of backtick toggles flips the state
    if backtick_count % 2 != 0 {
        !currently_inside
    } else {
        currently_inside
    }
}

/// Track triple-quote state (`"""` and `'''`) for Python.
/// Returns whether we're inside a multiline string after this line.
fn update_multiline_state_triple_quote(line: &str, currently_inside: bool) -> bool {
    let bytes = line.as_bytes();
    let mut state = currently_inside;
    let mut i = 0;

    while i < bytes.len() {
        if !state {
            // Outside a multiline string — skip single-line strings and look for triple quotes
            if bytes[i] == b'\\' {
                i += 2;
                continue;
            }
            if i + 2 < bytes.len()
                && ((bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
                    || (bytes[i] == b'\'' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\''))
            {
                state = true;
                i += 3;
                continue;
            }
            // Skip single-quoted or double-quoted string to avoid false triple-quote detection
            if bytes[i] == b'"' || bytes[i] == b'\'' {
                let quote = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1; // skip closing quote
                }
                continue;
            }
        } else {
            // Inside a multiline string — look for the closing triple quote
            if i + 2 < bytes.len()
                && ((bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
                    || (bytes[i] == b'\'' && bytes[i + 1] == b'\'' && bytes[i + 2] == b'\''))
            {
                state = false;
                i += 3;
                continue;
            }
        }
        i += 1;
    }

    state
}

/// Check whether the character at `pos` is inside a string literal.
///
/// Counts unescaped double-quote (and single-quote for Python's `#`) characters
/// before `pos`. If the count is odd, the position is inside a string literal.
fn is_inside_string_literal(line: &str, pos: usize) -> bool {
    let prefix = &line[..pos];
    let mut double_quotes = 0u32;
    let mut single_quotes = 0u32;
    let mut backticks = 0u32;
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
        } else if bytes[i] == b'`' {
            backticks += 1;
        }
        i += 1;
    }
    // Inside a string if any quote count is odd.
    double_quotes % 2 != 0 || single_quotes % 2 != 0 || backticks % 2 != 0
}

/// Returns `true` if the language uses `//` as a comment marker.
fn uses_slash_comments(language: Language) -> bool {
    matches!(
        language,
        Language::Go
            | Language::Rust
            | Language::JavaScript
            | Language::TypeScript
            | Language::Java
            | Language::CSharp
            | Language::Dart
            | Language::Php
    )
}

/// Returns `true` if the language uses `#` as a comment marker.
fn uses_hash_comments(language: Language) -> bool {
    matches!(language, Language::Python | Language::Php)
}

fn find_suppression_in_line(line: &str, language: Language) -> Option<(&str, String)> {
    const MARKER: &str = "chaffra:ignore";

    if uses_slash_comments(language) {
        let mut search_start = 0;
        while let Some(offset) = line[search_start..].find("//") {
            let comment_start = search_start + offset;
            if !is_inside_string_literal(line, comment_start) {
                let comment = &line[comment_start..];
                if let Some(pos) = comment.find(MARKER) {
                    let rest = &comment[pos + MARKER.len()..];
                    return Some((rest, comment.trim().to_owned()));
                }
                break; // Found a real comment but no marker — no suppression on this line
            }
            search_start = comment_start + 2; // Skip past this "//" and keep looking
        }
    }
    if uses_hash_comments(language) {
        let mut search_start = 0;
        while let Some(offset) = line[search_start..].find('#') {
            let comment_start = search_start + offset;
            if !is_inside_string_literal(line, comment_start) {
                let comment = &line[comment_start..];
                if let Some(pos) = comment.find(MARKER) {
                    let rest = &comment[pos + MARKER.len()..];
                    return Some((rest, comment.trim().to_owned()));
                }
                break; // Found a real comment but no marker — no suppression on this line
            }
            search_start = comment_start + 1; // Skip past this "#" and keep looking
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
        let cases: &[(&str, Language, &str)] = &[
            (
                "fmt.Println(\"// chaffra:ignore *\")\n",
                Language::Go,
                "Go string with //",
            ),
            (
                "let s = \"// chaffra:ignore *\";\n",
                Language::Go,
                "Go let string",
            ),
            (
                "x = \"# chaffra:ignore rule\"\n",
                Language::Python,
                "Python double-quoted string",
            ),
            (
                "x = '# chaffra:ignore rule'\n",
                Language::Python,
                "Python single-quoted string",
            ),
            (
                "fmt.Println(`// chaffra:ignore *`)\n",
                Language::Go,
                "Go raw string with backticks",
            ),
        ];
        for (src, lang, desc) in cases {
            let suppressions = scan_suppressions(src, *lang);
            assert!(
                suppressions.is_empty(),
                "should not detect suppression: {}",
                desc
            );
        }
    }

    #[test]
    fn test_hash_marker_not_suppression_in_go() {
        let src = "x := 1 # chaffra:ignore dead-code\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert!(
            suppressions.is_empty(),
            "hash marker should not be recognized as a comment in Go"
        );
    }

    #[test]
    fn test_slash_marker_not_suppression_in_python() {
        let src = "x = 1 // chaffra:ignore dead-code\n";
        let suppressions = scan_suppressions(src, Language::Python);
        assert!(
            suppressions.is_empty(),
            "slash marker should not be recognized as a comment in Python"
        );
    }

    #[test]
    fn test_is_line_suppressed_convenience() {
        let src = "package main\n// chaffra:ignore dead-code\nfunc unused() {}\n";
        let cases: &[(u32, &str, bool)] = &[
            (3, "dead-code", true),
            (3, "complexity", false),
            (1, "dead-code", false),
        ];
        for (line, rule, expected) in cases {
            assert_eq!(
                is_line_suppressed(src, *line, rule, Language::Go),
                *expected,
                "is_line_suppressed(line={}, rule={}) should be {}",
                line,
                rule,
                expected
            );
        }
    }

    #[test]
    fn test_escaped_quote_does_not_break_string_detection() {
        let src = "x := fmt.Sprintf(\"val=\\\"%s\\\"\" ) // chaffra:ignore dead-code\n";
        let suppressions = scan_suppressions(src, Language::Go);
        assert_eq!(suppressions.len(), 1);
    }

    #[test]
    fn test_suppression_found_after_in_string_delimiter() {
        let cases: &[(&str, Language, &str)] = &[
            (
                "url := \"https://example.com\" // chaffra:ignore dead-code\n",
                Language::Go,
                "Go: suppression after URL in string",
            ),
            (
                "x = \"has # inside\" # chaffra:ignore rule\n",
                Language::Python,
                "Python: suppression after hash in string",
            ),
        ];
        for (src, lang, desc) in cases {
            let suppressions = scan_suppressions(src, *lang);
            assert_eq!(suppressions.len(), 1, "should find suppression: {}", desc);
        }
    }

    #[test]
    fn test_suppression_inside_multiline_string_not_matched() {
        struct Case {
            src: &'static str,
            lang: Language,
            desc: &'static str,
            expected_count: usize,
        }

        let cases = &[
            Case {
                src: "msg := `\n// chaffra:ignore *\n`\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go raw string spanning 3 lines — suppression inside should not match",
                expected_count: 0,
            },
            Case {
                src: "msg = \"\"\"\n# chaffra:ignore rule\n\"\"\"\ndef unused(): pass\n",
                lang: Language::Python,
                desc: "Python triple-double-quoted string — suppression inside should not match",
                expected_count: 0,
            },
            Case {
                src: "msg = '''\n# chaffra:ignore rule\n'''\ndef unused(): pass\n",
                lang: Language::Python,
                desc: "Python triple-single-quoted string — suppression inside should not match",
                expected_count: 0,
            },
            Case {
                src: "msg := `// chaffra:ignore *`\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go raw string open+close same line — already handled by is_inside_string_literal",
                expected_count: 0,
            },
            Case {
                src: "msg := `\nsome content\n`\n// chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: real suppression after multiline string closes should match",
                expected_count: 1,
            },
            Case {
                src: "x = \"has\\\"quote\"\ny = \\\n\"\"\"\n# chaffra:ignore rule\n\"\"\"\ndef real(): pass\n",
                lang: Language::Python,
                desc: "Python: escaped chars in strings before triple-quote — no false suppression",
                expected_count: 0,
            },
        ];

        for case in cases {
            let suppressions = scan_suppressions(case.src, case.lang);
            assert_eq!(
                suppressions.len(),
                case.expected_count,
                "case '{}': expected {} suppressions, got {}",
                case.desc,
                case.expected_count,
                suppressions.len()
            );
        }
    }
}
