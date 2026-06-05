//! Tree-sitter parser wrapper supporting Go, Python, and stub parsing for
//! additional languages (PHP, Dart, C#, Rust).

use chaffra_core::diagnostic::Language;
use chaffra_core::error::{ChaffraError, Result};
use tree_sitter::{Parser, Tree};

/// Parse source code into a tree-sitter tree for the given language.
///
/// Languages with full tree-sitter grammar support (Go, Python) produce a
/// complete AST. Languages without a compiled grammar return an error; callers
/// should check `Language::has_tree_sitter_grammar()` before calling.
pub fn parse(source: &[u8], language: Language) -> Result<Tree> {
    let mut parser = Parser::new();
    let ts_language = match language {
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
        Language::Php | Language::Dart | Language::CSharp | Language::Rust => {
            return Err(ChaffraError::Parse(format!(
                "no tree-sitter grammar available for {language}; use stub parsing"
            )));
        }
    };
    parser
        .set_language(&ts_language)
        .map_err(|e| ChaffraError::Parse(format!("failed to set language: {e}")))?;

    parser
        .parse(source, None)
        .ok_or_else(|| ChaffraError::Parse("tree-sitter parse returned None".to_owned()))
}

/// Basic line-count information for languages without tree-sitter support.
#[derive(Debug, Clone)]
pub struct StubParseResult {
    /// Total lines in the file.
    pub total_lines: u32,
    /// Non-empty, non-comment lines (rough approximation).
    pub code_lines: u32,
}

/// Perform a basic stub parse for languages without tree-sitter grammars.
///
/// Returns line counts only -- no AST, no symbol extraction.
pub fn stub_parse(source: &[u8]) -> StubParseResult {
    let text = String::from_utf8_lossy(source);
    let total_lines = text.lines().count() as u32;
    let code_lines = text
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with('#')
        })
        .count() as u32;
    StubParseResult {
        total_lines,
        code_lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_go() {
        let src = b"package main\n\nfunc main() {}\n";
        let tree = parse(src, Language::Go).unwrap();
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn test_parse_python() {
        let src = b"def hello():\n    pass\n";
        let tree = parse(src, Language::Python).unwrap();
        assert_eq!(tree.root_node().kind(), "module");
    }

    #[test]
    fn test_parse_go_function() {
        let src = b"package main\n\nfunc Add(a, b int) int {\n    return a + b\n}\n";
        let tree = parse(src, Language::Go).unwrap();
        let root = tree.root_node();
        let mut found_func = false;
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() == "function_declaration" {
                found_func = true;
            }
        }
        assert!(found_func, "should find function_declaration node");
    }

    #[test]
    fn test_parse_python_class() {
        let src = b"class Foo:\n    def bar(self):\n        pass\n";
        let tree = parse(src, Language::Python).unwrap();
        let root = tree.root_node();
        let mut found_class = false;
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            if child.kind() == "class_definition" {
                found_class = true;
            }
        }
        assert!(found_class, "should find class_definition node");
    }

    #[test]
    fn test_parse_unsupported_language_returns_error() {
        let src = b"fn main() {}";
        let result = parse(src, Language::Rust);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("no tree-sitter grammar"),
            "error should mention missing grammar: {err}"
        );
    }

    #[test]
    fn test_stub_parse_basic() {
        let src = b"// comment\nfn main() {\n    println!(\"hello\");\n}\n\n";
        let result = stub_parse(src);
        assert_eq!(result.total_lines, 5);
        // "fn main() {", "    println...", "}" are code lines
        assert!(result.code_lines >= 3);
    }

    #[test]
    fn test_stub_parse_empty() {
        let result = stub_parse(b"");
        assert_eq!(result.total_lines, 0);
        assert_eq!(result.code_lines, 0);
    }

    #[test]
    fn test_stub_parse_all_comments() {
        let src = b"// line 1\n// line 2\n# line 3\n";
        let result = stub_parse(src);
        assert_eq!(result.total_lines, 3);
        assert_eq!(result.code_lines, 0);
    }
}
