//! Language-aware tokenizer for clone detection.
//!
//! Strips comments and whitespace, then normalizes tokens according to the
//! selected mode: strict, mild (normalize literals), weak (normalize identifiers),
//! or semantic (normalize control flow).

use chaffra_core::diagnostic::Language;

/// Normalization mode for clone detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormMode {
    /// Exact token match: only strip comments and whitespace.
    Strict,
    /// Normalize literal values (strings, numbers) to placeholders.
    Mild,
    /// Normalize identifiers to a common placeholder.
    Weak,
    /// Normalize control flow structures (if/else/for/while) to a common token.
    Semantic,
}

/// A normalized token with source line information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Token {
    /// Normalized token text.
    pub text: String,
    /// 1-based source line.
    pub line: u32,
}

/// Tokenize source code for the given language and normalization mode.
///
/// Strips comments and whitespace, then normalizes according to the mode.
pub fn tokenize(source: &str, lang: Language, mode: NormMode) -> Vec<Token> {
    let raw = raw_tokenize(source, lang);
    raw.into_iter()
        .map(|t| Token {
            text: normalize(&t.text, mode, lang),
            line: t.line,
        })
        .collect()
}

/// Split source into raw tokens (words, operators, punctuation), stripping comments.
fn raw_tokenize(source: &str, lang: Language) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut string_char: char = '"';

    for (line_idx, line) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;

        // Handle block comments.
        if in_block_comment {
            while i < chars.len() {
                if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
                    in_block_comment = false;
                    i += 2;
                    break;
                }
                i += 1;
            }
            if in_block_comment {
                continue;
            }
        }

        while i < chars.len() {
            let ch = chars[i];

            // Skip whitespace.
            if ch.is_whitespace() {
                i += 1;
                continue;
            }

            // Line comments.
            if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '/' {
                break;
            }

            // Python line comments.
            if matches!(lang, Language::Python) && ch == '#' && !in_string {
                break;
            }

            // Block comments.
            if i + 1 < chars.len() && chars[i] == '/' && chars[i + 1] == '*' {
                in_block_comment = true;
                i += 2;
                while i < chars.len() {
                    if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '/' {
                        in_block_comment = false;
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // String literals.
            if (ch == '"' || ch == '\'' || ch == '`') && !in_string {
                in_string = true;
                string_char = ch;
                let mut s = String::new();
                s.push(ch);
                i += 1;
                while i < chars.len() {
                    let sc = chars[i];
                    s.push(sc);
                    if sc == string_char && (i == 0 || chars[i - 1] != '\\') {
                        in_string = false;
                        break;
                    }
                    i += 1;
                }
                i += 1;
                tokens.push(Token {
                    text: s,
                    line: line_num,
                });
                continue;
            }

            // Numbers.
            if ch.is_ascii_digit()
                || (ch == '.' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit())
            {
                let mut num = String::new();
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '.' || chars[i] == '_')
                {
                    num.push(chars[i]);
                    i += 1;
                }
                tokens.push(Token {
                    text: num,
                    line: line_num,
                });
                continue;
            }

            // Identifiers and keywords.
            if ch.is_alphabetic() || ch == '_' {
                let mut ident = String::new();
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    ident.push(chars[i]);
                    i += 1;
                }
                tokens.push(Token {
                    text: ident,
                    line: line_num,
                });
                continue;
            }

            // Multi-character operators.
            if i + 1 < chars.len() {
                let two: String = chars[i..i + 2].iter().collect();
                if matches!(
                    two.as_str(),
                    ":=" | "=="
                        | "!="
                        | "<="
                        | ">="
                        | "&&"
                        | "||"
                        | "+="
                        | "-="
                        | "*="
                        | "/="
                        | "++"
                        | "--"
                        | "->"
                        | "=>"
                ) {
                    tokens.push(Token {
                        text: two,
                        line: line_num,
                    });
                    i += 2;
                    continue;
                }
            }

            // Single character operators and punctuation.
            tokens.push(Token {
                text: ch.to_string(),
                line: line_num,
            });
            i += 1;
        }

        // Reset string state at line end for non-backtick strings.
        if in_string && string_char != '`' {
            in_string = false;
        }
    }

    tokens
}

/// Keywords for various languages.
fn is_keyword(text: &str, lang: Language) -> bool {
    match lang {
        Language::Go => matches!(
            text,
            "break"
                | "case"
                | "chan"
                | "const"
                | "continue"
                | "default"
                | "defer"
                | "else"
                | "fallthrough"
                | "for"
                | "func"
                | "go"
                | "goto"
                | "if"
                | "import"
                | "interface"
                | "map"
                | "package"
                | "range"
                | "return"
                | "select"
                | "struct"
                | "switch"
                | "type"
                | "var"
        ),
        Language::Python => matches!(
            text,
            "False"
                | "None"
                | "True"
                | "and"
                | "as"
                | "assert"
                | "async"
                | "await"
                | "break"
                | "class"
                | "continue"
                | "def"
                | "del"
                | "elif"
                | "else"
                | "except"
                | "finally"
                | "for"
                | "from"
                | "global"
                | "if"
                | "import"
                | "in"
                | "is"
                | "lambda"
                | "nonlocal"
                | "not"
                | "or"
                | "pass"
                | "raise"
                | "return"
                | "try"
                | "while"
                | "with"
                | "yield"
        ),
        Language::JavaScript | Language::TypeScript => matches!(
            text,
            "break"
                | "case"
                | "catch"
                | "class"
                | "const"
                | "continue"
                | "debugger"
                | "default"
                | "delete"
                | "do"
                | "else"
                | "export"
                | "extends"
                | "finally"
                | "for"
                | "function"
                | "if"
                | "import"
                | "in"
                | "instanceof"
                | "let"
                | "new"
                | "of"
                | "return"
                | "super"
                | "switch"
                | "this"
                | "throw"
                | "try"
                | "typeof"
                | "var"
                | "void"
                | "while"
                | "with"
                | "yield"
                | "async"
                | "await"
        ),
        Language::Java => matches!(
            text,
            "abstract"
                | "assert"
                | "boolean"
                | "break"
                | "byte"
                | "case"
                | "catch"
                | "char"
                | "class"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extends"
                | "final"
                | "finally"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "implements"
                | "import"
                | "instanceof"
                | "int"
                | "interface"
                | "long"
                | "native"
                | "new"
                | "package"
                | "private"
                | "protected"
                | "public"
                | "return"
                | "short"
                | "static"
                | "strictfp"
                | "super"
                | "switch"
                | "synchronized"
                | "this"
                | "throw"
                | "throws"
                | "transient"
                | "try"
                | "void"
                | "volatile"
                | "while"
        ),
        _ => false,
    }
}

/// Control flow keywords.
fn is_control_flow(text: &str) -> bool {
    matches!(
        text,
        "if" | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "break"
            | "continue"
            | "return"
            | "try"
            | "catch"
            | "finally"
            | "throw"
            | "elif"
            | "except"
            | "with"
            | "select"
            | "defer"
            | "go"
            | "range"
            | "yield"
            | "async"
            | "await"
    )
}

/// Check if a token looks like a string literal.
fn is_string_literal(text: &str) -> bool {
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
        || (text.starts_with('`') && text.ends_with('`'))
}

/// Check if a token looks like a number literal.
fn is_number_literal(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit() || c == '.')
}

/// Normalize a token according to the selected mode.
fn normalize(text: &str, mode: NormMode, lang: Language) -> String {
    match mode {
        NormMode::Strict => text.to_owned(),
        NormMode::Mild => {
            // Normalize string and number literals.
            if is_string_literal(text) {
                "$STR".to_owned()
            } else if is_number_literal(text) {
                "$NUM".to_owned()
            } else {
                text.to_owned()
            }
        }
        NormMode::Weak => {
            // Normalize literals + identifiers (but not keywords).
            if is_string_literal(text) {
                "$STR".to_owned()
            } else if is_number_literal(text) {
                "$NUM".to_owned()
            } else if !is_keyword(text, lang)
                && text
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
            {
                "$ID".to_owned()
            } else {
                text.to_owned()
            }
        }
        NormMode::Semantic => {
            // Normalize literals + identifiers + control flow.
            if is_string_literal(text) {
                "$STR".to_owned()
            } else if is_number_literal(text) {
                "$NUM".to_owned()
            } else if is_control_flow(text) {
                "$CTRL".to_owned()
            } else if !is_keyword(text, lang)
                && text
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
            {
                "$ID".to_owned()
            } else {
                text.to_owned()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_tokenize_go() {
        let src = "package main\n\nfunc main() {\n    fmt.Println(\"hello\")\n}\n";
        let tokens = raw_tokenize(src, Language::Go);
        let texts: Vec<&str> = tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(texts.contains(&"package"));
        assert!(texts.contains(&"main"));
        assert!(texts.contains(&"func"));
        assert!(texts.contains(&"fmt"));
        assert!(texts.contains(&"Println"));
    }

    #[test]
    fn test_raw_tokenize_strips_line_comments() {
        let src = "x := 1 // this is a comment\ny := 2\n";
        let tokens = raw_tokenize(src, Language::Go);
        let texts: Vec<&str> = tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(!texts.contains(&"this"));
        assert!(!texts.contains(&"comment"));
        assert!(texts.contains(&"x"));
        assert!(texts.contains(&"y"));
    }

    #[test]
    fn test_raw_tokenize_strips_python_comments() {
        let src = "x = 1  # comment\ny = 2\n";
        let tokens = raw_tokenize(src, Language::Python);
        let texts: Vec<&str> = tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(!texts.contains(&"comment"));
        assert!(texts.contains(&"x"));
    }

    #[test]
    fn test_normalize_strict() {
        assert_eq!(normalize("hello", NormMode::Strict, Language::Go), "hello");
        assert_eq!(normalize("42", NormMode::Strict, Language::Go), "42");
        assert_eq!(
            normalize("\"str\"", NormMode::Strict, Language::Go),
            "\"str\""
        );
    }

    #[test]
    fn test_normalize_mild() {
        assert_eq!(normalize("hello", NormMode::Mild, Language::Go), "hello");
        assert_eq!(normalize("42", NormMode::Mild, Language::Go), "$NUM");
        assert_eq!(normalize("\"str\"", NormMode::Mild, Language::Go), "$STR");
    }

    #[test]
    fn test_normalize_weak() {
        assert_eq!(normalize("myVar", NormMode::Weak, Language::Go), "$ID");
        assert_eq!(normalize("func", NormMode::Weak, Language::Go), "func");
        assert_eq!(normalize("42", NormMode::Weak, Language::Go), "$NUM");
    }

    #[test]
    fn test_normalize_semantic() {
        assert_eq!(normalize("if", NormMode::Semantic, Language::Go), "$CTRL");
        assert_eq!(normalize("for", NormMode::Semantic, Language::Go), "$CTRL");
        assert_eq!(normalize("myVar", NormMode::Semantic, Language::Go), "$ID");
    }

    #[test]
    fn test_tokenize_preserves_lines() {
        let src = "x := 1\ny := 2\n";
        let tokens = tokenize(src, Language::Go, NormMode::Strict);
        let line1_tokens: Vec<_> = tokens.iter().filter(|t| t.line == 1).collect();
        let line2_tokens: Vec<_> = tokens.iter().filter(|t| t.line == 2).collect();
        assert!(!line1_tokens.is_empty());
        assert!(!line2_tokens.is_empty());
    }

    #[test]
    fn test_is_keyword() {
        assert!(is_keyword("func", Language::Go));
        assert!(is_keyword("def", Language::Python));
        assert!(is_keyword("function", Language::JavaScript));
        assert!(is_keyword("class", Language::Java));
        assert!(!is_keyword("myFunc", Language::Go));
    }

    #[test]
    fn test_block_comment_stripping() {
        let src = "x := 1\n/* block\ncomment */\ny := 2\n";
        let tokens = raw_tokenize(src, Language::Go);
        let texts: Vec<&str> = tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(!texts.contains(&"block"));
        assert!(!texts.contains(&"comment"));
        assert!(texts.contains(&"x"));
        assert!(texts.contains(&"y"));
    }

    #[test]
    fn test_multi_char_operators() {
        let src = "x := y == z && a != b\n";
        let tokens = raw_tokenize(src, Language::Go);
        let texts: Vec<&str> = tokens.iter().map(|t| t.text.as_str()).collect();
        assert!(texts.contains(&":="));
        assert!(texts.contains(&"=="));
        assert!(texts.contains(&"&&"));
        assert!(texts.contains(&"!="));
    }
}
