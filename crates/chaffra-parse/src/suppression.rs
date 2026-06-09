//! Suppression comment scanning for `// chaffra:ignore` and `# chaffra:ignore`.

use chaffra_core::diagnostic::Language;

/// Tracks which type of multiline string delimiter is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultilineState {
    /// Not inside any multiline string.
    None,
    /// Inside a Go raw string (backtick-delimited).
    InBacktick,
    /// Inside a Python `"""` string.
    InTripleDouble,
    /// Inside a Python `'''` string.
    InTripleSingle,
}

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
    let mut multiline_state = MultilineState::None;

    for (idx, line) in source.lines().enumerate() {
        let was_inside = multiline_state != MultilineState::None;
        let (new_state, close_pos) = update_multiline_state(line, language, multiline_state);
        multiline_state = new_state;

        if was_inside {
            if let Some(pos) = close_pos {
                // Multiline string closed on this line — scan remainder
                let remainder = &line[pos..];
                if let Some((rest, text)) = find_suppression_in_line(remainder, language) {
                    let rules = parse_suppression_rules(rest);
                    suppressions.push(Suppression {
                        line: idx as u32 + 1,
                        rules,
                        text,
                    });
                }
            }
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
/// Returns `(new_state, close_pos)` where `new_state` indicates whether we are inside a multiline
/// string after this line, and `close_pos` is the byte index right after the first closing
/// delimiter if the line started inside a multiline string and the string closed on this line.
fn update_multiline_state(
    line: &str,
    language: Language,
    state: MultilineState,
) -> (MultilineState, Option<usize>) {
    if uses_slash_comments(language) {
        update_multiline_state_backtick(line, state)
    } else {
        update_multiline_state_triple_quote(line, state)
    }
}

/// Track backtick raw string state across a single line.
///
/// Uses a `in_raw` boolean that reflects the actual current state at each byte,
/// toggling on each unquoted backtick. Double-quote tracking works correctly
/// in suffixes after a raw string closes.
///
/// Returns `(new_state, close_pos)` where `close_pos` is the byte index right after
/// the first closing backtick if we started inside a raw string and it closed.
fn update_multiline_state_backtick(
    line: &str,
    state: MultilineState,
) -> (MultilineState, Option<usize>) {
    let currently_inside = state == MultilineState::InBacktick;
    let bytes = line.as_bytes();
    let mut in_raw = currently_inside;
    let mut in_double_quote = false;
    let mut first_close_pos: Option<usize> = None;
    let mut i = 0;

    while i < bytes.len() {
        if !in_raw && !in_double_quote && bytes[i] == b'\\' {
            // Skip escaped character (only relevant outside raw strings)
            i += 2;
            continue;
        }
        if in_raw {
            // Inside a raw string — only backtick exits
            if bytes[i] == b'`' {
                in_raw = false;
                if currently_inside && first_close_pos.is_none() {
                    first_close_pos = Some(i + 1);
                }
            }
        } else {
            // Normal code — track double quotes and backticks
            if in_double_quote && bytes[i] == b'\\' {
                // Skip escaped character inside double-quoted string
                i += 2;
                continue;
            }
            if !in_double_quote && bytes[i] == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                // Real comment starts here — stop processing
                break;
            }
            if bytes[i] == b'\'' && !in_double_quote {
                // Skip rune literal contents (e.g., '`' in Go)
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    if bytes[i] == b'\\' {
                        i += 1; // skip escaped char
                    }
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1; // skip closing quote
                }
                continue;
            }
            if bytes[i] == b'"' {
                in_double_quote = !in_double_quote;
            } else if bytes[i] == b'`' && !in_double_quote {
                in_raw = true;
            }
        }
        i += 1;
    }

    let new_state = if in_raw {
        MultilineState::InBacktick
    } else {
        MultilineState::None
    };

    let close_pos = if currently_inside {
        first_close_pos
    } else {
        None
    };

    (new_state, close_pos)
}

/// Track triple-quote state (`"""` and `'''`) for Python.
///
/// Tracks which specific delimiter opened the string so that `'''` inside `"""`
/// (and vice versa) does not incorrectly close it.
///
/// Returns `(new_state, close_pos)` where `close_pos` is the byte index right after
/// the first closing triple-quote if we started inside a string and it closed.
fn update_multiline_state_triple_quote(
    line: &str,
    state: MultilineState,
) -> (MultilineState, Option<usize>) {
    let bytes = line.as_bytes();
    let mut current = state;
    let mut first_close_pos: Option<usize> = None;
    let mut i = 0;

    while i < bytes.len() {
        match current {
            MultilineState::None | MultilineState::InBacktick => {
                // Outside a multiline string — skip single-line strings and look for triple quotes
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if i + 2 < bytes.len()
                    && bytes[i] == b'"'
                    && bytes[i + 1] == b'"'
                    && bytes[i + 2] == b'"'
                {
                    current = MultilineState::InTripleDouble;
                    i += 3;
                    continue;
                }
                if i + 2 < bytes.len()
                    && bytes[i] == b'\''
                    && bytes[i + 1] == b'\''
                    && bytes[i + 2] == b'\''
                {
                    current = MultilineState::InTripleSingle;
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
                // Hash comment starts here — stop processing (not inside a string)
                if bytes[i] == b'#' {
                    break;
                }
            }
            MultilineState::InTripleDouble => {
                // Inside `"""` — only `"""` closes it
                if i + 2 < bytes.len()
                    && bytes[i] == b'"'
                    && bytes[i + 1] == b'"'
                    && bytes[i + 2] == b'"'
                {
                    current = MultilineState::None;
                    if state != MultilineState::None && first_close_pos.is_none() {
                        first_close_pos = Some(i + 3);
                    }
                    i += 3;
                    continue;
                }
            }
            MultilineState::InTripleSingle => {
                // Inside `'''` — only `'''` closes it
                if i + 2 < bytes.len()
                    && bytes[i] == b'\''
                    && bytes[i + 1] == b'\''
                    && bytes[i + 2] == b'\''
                {
                    current = MultilineState::None;
                    if state != MultilineState::None && first_close_pos.is_none() {
                        first_close_pos = Some(i + 3);
                    }
                    i += 3;
                    continue;
                }
            }
        }
        i += 1;
    }

    // Only report close_pos if we actually started inside
    let close_pos = if state != MultilineState::None {
        first_close_pos
    } else {
        None
    };

    (current, close_pos)
}

/// Check whether the character at `pos` is inside a string literal.
///
/// Uses a state machine to properly handle nested delimiters (e.g., a backtick
/// inside a double-quoted string does not start a raw string).
fn is_inside_string_literal(line: &str, pos: usize) -> bool {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        InDouble,
        InSingle,
        InBacktick,
    }

    let prefix = &line[..pos];
    let bytes = prefix.as_bytes();
    let mut state = State::Normal;
    let mut i = 0;

    while i < bytes.len() {
        match state {
            State::Normal => {
                if bytes[i] == b'\\' {
                    // Skip escaped character in normal context.
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    state = State::InDouble;
                } else if bytes[i] == b'\'' {
                    state = State::InSingle;
                } else if bytes[i] == b'`' {
                    state = State::InBacktick;
                }
            }
            State::InDouble => {
                if bytes[i] == b'\\' {
                    // Skip escaped character inside double-quoted string.
                    i += 2;
                    continue;
                }
                if bytes[i] == b'"' {
                    state = State::Normal;
                }
            }
            State::InSingle => {
                if bytes[i] == b'\\' {
                    // Skip escaped character inside single-quoted string.
                    i += 2;
                    continue;
                }
                if bytes[i] == b'\'' {
                    state = State::Normal;
                }
            }
            State::InBacktick => {
                // Go raw strings have no escape sequences — only backtick closes.
                if bytes[i] == b'`' {
                    state = State::Normal;
                }
            }
        }
        i += 1;
    }

    state != State::Normal
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
            (
                "fmt.Println(\"`\") // chaffra:ignore dead-code\n",
                Language::Go,
                "Go: backtick inside double-quoted string does not affect state",
            ),
            (
                "x := `raw` // chaffra:ignore dead-code\n",
                Language::Go,
                "Go: suppression after closed backtick raw string",
            ),
            (
                "x = 'esc\\'d' # chaffra:ignore dead-code\n",
                Language::Python,
                "Python: suppression after single-quoted string with escape",
            ),
            (
                "\\x // chaffra:ignore dead-code\n",
                Language::Go,
                "Go: backslash in normal context before suppression",
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
            Case {
                src: "msg := `\nsome content\n` // chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: closing backtick with trailing suppression on same line",
                expected_count: 1,
            },
            Case {
                src: "msg = \"\"\"\nsome content\n\"\"\" # chaffra:ignore rule\ndef unused(): pass\n",
                lang: Language::Python,
                desc: "Python: closing triple-quote with trailing suppression on same line",
                expected_count: 1,
            },
            Case {
                src: "msg = \"\"\"\n''' # chaffra:ignore dead-code\n\"\"\"\ndef unused(): pass\n",
                lang: Language::Python,
                desc: "Python: ''' inside \"\"\" does not close the string — no false suppression",
                expected_count: 0,
            },
            Case {
                src: "msg = '''\n\"\"\" # chaffra:ignore dead-code\n'''\ndef unused(): pass\n",
                lang: Language::Python,
                desc: "Python: \"\"\" inside ''' does not close the string — no false suppression",
                expected_count: 0,
            },
            Case {
                src: "msg := `\nraw content\n` ; x := fmt.Println(\"`\") \n// chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: backtick inside double-quoted string after raw string close does not corrupt state",
                expected_count: 1,
            },
            Case {
                src: "// has a backtick: `\n// chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: backtick in comment should not open raw string state",
                expected_count: 1,
            },
            Case {
                src: "# has triple quote: \"\"\"\n# chaffra:ignore dead-code\ndef unused(): pass\n",
                lang: Language::Python,
                desc: "Python: triple-quote in comment should not open multiline string state",
                expected_count: 1,
            },
            Case {
                src: "fmt.Sprintf(\"val=\\\"%s`end\\\"\") \n// chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: escaped quote before backtick in double-quoted string should not open raw string state",
                expected_count: 1,
            },
            Case {
                src: "x := '`'\n// chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: rune literal with backtick does not open raw string state",
                expected_count: 1,
            },
            Case {
                src: "x := '\\`'\n// chaffra:ignore dead-code\nfunc unused() {}\n",
                lang: Language::Go,
                desc: "Go: rune literal with escaped backtick does not open raw string state",
                expected_count: 1,
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
