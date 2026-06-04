//! Tree-sitter parser wrapper supporting Go and Python.

use chaffra_core::diagnostic::Language;
use chaffra_core::error::{ChaffraError, Result};
use tree_sitter::{Parser, Tree};

/// Parse source code into a tree-sitter tree for the given language.
pub fn parse(source: &[u8], language: Language) -> Result<Tree> {
    let mut parser = Parser::new();
    let ts_language = match language {
        Language::Go => tree_sitter_go::LANGUAGE.into(),
        Language::Python => tree_sitter_python::LANGUAGE.into(),
    };
    parser
        .set_language(&ts_language)
        .map_err(|e| ChaffraError::Parse(format!("failed to set language: {e}")))?;

    parser
        .parse(source, None)
        .ok_or_else(|| ChaffraError::Parse("tree-sitter parse returned None".to_owned()))
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
        // Find function_declaration node
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
}
