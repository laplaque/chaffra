//! Go framework detection: gin, echo, cobra.
//!
//! Walks the tree-sitter AST looking for patterns specific to each framework:
//! - **gin**: `r.GET("/path", handler)`, `r.POST(...)`, etc.
//! - **echo**: `e.GET("/path", handler)`, `e.POST(...)`, etc.
//! - **cobra**: `&cobra.Command{...}` with `Run:` or `RunE:` fields.

use crate::detect::FrameworkEntry;
use tree_sitter::{Node, Tree};

/// HTTP methods used by gin and echo routers.
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "Any", "Handle",
];

/// Detect Go framework entry points in a parsed tree.
pub fn detect_go_frameworks(tree: &Tree, source: &[u8], file: &str) -> Vec<FrameworkEntry> {
    let root = tree.root_node();
    let src = std::str::from_utf8(source).unwrap_or("");

    let mut entries = Vec::new();

    // Check imports for framework detection signals.
    let has_gin = src.contains("gin-gonic/gin") || src.contains("\"github.com/gin-gonic/gin\"");
    let has_echo = src.contains("labstack/echo") || src.contains("\"github.com/labstack/echo");
    let has_cobra = src.contains("spf13/cobra") || src.contains("\"github.com/spf13/cobra\"");

    walk_go_node(
        root,
        source,
        file,
        has_gin,
        has_echo,
        has_cobra,
        &mut entries,
    );

    entries
}

/// Recursively walk the AST for framework patterns.
fn walk_go_node(
    node: Node,
    source: &[u8],
    file: &str,
    has_gin: bool,
    has_echo: bool,
    has_cobra: bool,
    entries: &mut Vec<FrameworkEntry>,
) {
    // Pattern: method call like `r.GET("/path", handlerFunc)`
    if node.kind() == "call_expression" {
        if let Some(entry) = check_router_call(node, source, file, has_gin, has_echo) {
            entries.push(entry);
        }
    }

    // Pattern: cobra command literal `&cobra.Command{...Run: func...}`
    if has_cobra && node.kind() == "composite_literal" {
        if let Some(entry) = check_cobra_command(node, source, file) {
            entries.push(entry);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_go_node(child, source, file, has_gin, has_echo, has_cobra, entries);
    }
}

/// Check if a call expression matches a router handler registration pattern.
///
/// Matches patterns like `r.GET("/path", handlerFunc)` or `group.POST("/path", handler)`.
fn check_router_call(
    node: Node,
    source: &[u8],
    file: &str,
    has_gin: bool,
    has_echo: bool,
) -> Option<FrameworkEntry> {
    // The call_expression should have a selector_expression as its function.
    let func_node = node.child_by_field_name("function")?;
    if func_node.kind() != "selector_expression" {
        return None;
    }

    let method_node = func_node.child_by_field_name("field")?;
    let method_name = node_text(method_node, source)?;

    if !HTTP_METHODS.contains(&method_name.as_str()) {
        return None;
    }

    // Extract the handler argument (last non-string argument in the argument list).
    let args_node = node.child_by_field_name("arguments")?;
    let handler_name = extract_handler_arg(args_node, source);

    let framework = if has_gin {
        "gin"
    } else if has_echo {
        "echo"
    } else {
        return None;
    };

    let name = handler_name.unwrap_or_else(|| format!("{method_name} handler"));

    Some(FrameworkEntry {
        framework: framework.to_owned(),
        kind: "handler".to_owned(),
        name,
        file: file.to_owned(),
        line: node.start_position().row as u32 + 1,
        confidence: 0.9,
    })
}

/// Extract the handler function name from a router call's argument list.
///
/// In `r.GET("/path", handlerFunc)` we want "handlerFunc".
/// In `r.GET("/path", pkg.Handler)` we want "pkg.Handler".
fn extract_handler_arg(args_node: Node, source: &[u8]) -> Option<String> {
    let count = args_node.named_child_count() as u32;
    if count < 2 {
        return None;
    }
    // The handler is typically the last argument.
    let last = args_node.named_child(count - 1)?;
    let text = node_text(last, source)?;
    // Skip if it's a function literal (anonymous handler).
    if text.starts_with("func") {
        return None;
    }
    Some(text)
}

/// Check if a composite literal is a cobra.Command definition.
///
/// Matches `&cobra.Command{ Use: "name", Run: func(...) { ... } }`.
fn check_cobra_command(node: Node, source: &[u8], file: &str) -> Option<FrameworkEntry> {
    let type_node = node.child_by_field_name("type")?;
    let type_text = node_text(type_node, source)?;

    if !type_text.contains("cobra.Command") && !type_text.contains("Command") {
        return None;
    }

    // Look for "cobra" in the type or surrounding context.
    let src = std::str::from_utf8(source).unwrap_or("");
    if !src.contains("cobra") {
        return None;
    }

    // Extract the command name from the "Use" field if present.
    let body = node.child_by_field_name("body")?;
    let mut command_name = None;
    let mut has_run = false;

    let mut cursor = body.walk();
    for child in body.children(&mut cursor) {
        if child.kind() == "keyed_element" || child.kind() == "literal_element" {
            let key = child.child(0)?;
            let key_text = node_text(key, source)?;
            match key_text.as_str() {
                "Use" => {
                    // Value is a string literal.
                    let child_count = child.child_count() as u32;
                    if let Some(val) = child_count.checked_sub(1).and_then(|i| child.child(i)) {
                        let val_text = node_text(val, source)?;
                        command_name = Some(val_text.trim_matches('"').to_owned());
                    }
                }
                "Run" | "RunE" => {
                    has_run = true;
                }
                _ => {}
            }
        }
    }

    if !has_run {
        return None;
    }

    Some(FrameworkEntry {
        framework: "cobra".to_owned(),
        kind: "command".to_owned(),
        name: command_name.unwrap_or_else(|| "cobra command".to_owned()),
        file: file.to_owned(),
        line: node.start_position().row as u32 + 1,
        confidence: 0.85,
    })
}

/// Get the text content of a node.
fn node_text(node: Node, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?;
    Some(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::Language;
    use chaffra_parse::parser;

    fn parse_go(source: &[u8]) -> Tree {
        parser::parse(source, Language::Go).unwrap()
    }

    #[test]
    fn test_detect_gin_get_handler() {
        let source = br#"package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/hello", helloHandler)
    r.Run()
}
"#;
        let tree = parse_go(source);
        let entries = detect_go_frameworks(&tree, source, "main.go");
        assert!(!entries.is_empty());
        assert_eq!(entries[0].framework, "gin");
        assert_eq!(entries[0].kind, "handler");
        assert_eq!(entries[0].name, "helloHandler");
    }

    #[test]
    fn test_detect_gin_multiple_methods() {
        let source = br#"package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.GET("/hello", getHandler)
    r.POST("/users", createHandler)
    r.PUT("/users/:id", updateHandler)
    r.DELETE("/users/:id", deleteHandler)
    r.Run()
}
"#;
        let tree = parse_go(source);
        let entries = detect_go_frameworks(&tree, source, "main.go");
        assert_eq!(
            entries.len(),
            4,
            "should detect all 4 handlers: {entries:?}"
        );
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"getHandler"));
        assert!(names.contains(&"createHandler"));
        assert!(names.contains(&"updateHandler"));
        assert!(names.contains(&"deleteHandler"));
    }

    #[test]
    fn test_detect_echo_handlers() {
        let source = br#"package main

import "github.com/labstack/echo/v4"

func main() {
    e := echo.New()
    e.GET("/hello", helloHandler)
    e.POST("/users", createUser)
    e.Start(":8080")
}
"#;
        let tree = parse_go(source);
        let entries = detect_go_frameworks(&tree, source, "main.go");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.framework == "echo"));
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_detect_cobra_command() {
        let source = br#"package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
    Use:   "myapp",
    Short: "My application",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("hello")
    },
}
"#;
        let tree = parse_go(source);
        let entries = detect_go_frameworks(&tree, source, "cmd/root.go");
        assert!(
            !entries.is_empty(),
            "should detect cobra command: {entries:?}"
        );
        assert_eq!(entries[0].framework, "cobra");
        assert_eq!(entries[0].kind, "command");
    }

    #[test]
    fn test_no_framework_plain_go() {
        let source = b"package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n";
        let tree = parse_go(source);
        let entries = detect_go_frameworks(&tree, source, "main.go");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_gin_import_without_handler_calls() {
        let source = br#"package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default()
    r.Run()
}
"#;
        let tree = parse_go(source);
        let entries = detect_go_frameworks(&tree, source, "main.go");
        // No handler registrations, so no entries.
        assert!(entries.is_empty());
    }

    #[test]
    fn test_node_text_helper() {
        let source = b"package main\nfunc hello() {}\n";
        let tree = parse_go(source);
        let root = tree.root_node();
        let text = node_text(root, source);
        assert!(text.is_some());
        assert!(text.unwrap().contains("package main"));
    }
}
