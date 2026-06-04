//! Symbol extraction from tree-sitter ASTs: functions, types, imports, exports.

use chaffra_core::diagnostic::Language;
use tree_sitter::{Node, Tree};

/// A symbol extracted from source code.
#[derive(Debug, Clone, PartialEq)]
pub struct Symbol {
    /// Symbol name.
    pub name: String,
    /// Kind of symbol.
    pub kind: SymbolKind,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Whether this symbol is exported/public.
    pub exported: bool,
    /// File this symbol was found in.
    pub file: String,
}

/// Kind of symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    Function,
    Type,
    Import,
    Variable,
}

impl std::fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolKind::Function => write!(f, "function"),
            SymbolKind::Type => write!(f, "type"),
            SymbolKind::Import => write!(f, "import"),
            SymbolKind::Variable => write!(f, "variable"),
        }
    }
}

/// An import statement extracted from source code.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportInfo {
    /// The imported path or module name.
    pub path: String,
    /// Optional alias.
    pub alias: Option<String>,
    /// Specific names imported (for `from X import Y` style).
    pub names: Vec<String>,
    /// 1-based line number.
    pub line: u32,
}

/// A reference to a symbol (usage/call site).
#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    /// The name being referenced.
    pub name: String,
    /// File containing the reference.
    pub file: String,
    /// 1-based line number.
    pub line: u32,
}

/// Extract all symbols from a parsed tree.
pub fn extract_symbols(tree: &Tree, source: &[u8], language: Language, file: &str) -> Vec<Symbol> {
    let root = tree.root_node();
    match language {
        Language::Go => extract_go_symbols(root, source, file),
        Language::Python => extract_python_symbols(root, source, file),
    }
}

/// Extract all imports from a parsed tree.
pub fn extract_imports(tree: &Tree, source: &[u8], language: Language) -> Vec<ImportInfo> {
    let root = tree.root_node();
    match language {
        Language::Go => extract_go_imports(root, source),
        Language::Python => extract_python_imports(root, source),
    }
}

/// Extract all references (identifiers used) from a parsed tree.
pub fn extract_references(
    tree: &Tree,
    source: &[u8],
    language: Language,
    file: &str,
) -> Vec<Reference> {
    let root = tree.root_node();
    let mut refs = Vec::new();
    collect_identifiers(root, source, file, language, &mut refs);
    refs
}

// --- Go symbol extraction ---

fn extract_go_symbols(root: Node<'_>, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source);
                    let exported = name.starts_with(char::is_uppercase);
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Function,
                        start_line: child.start_position().row as u32 + 1,
                        end_line: child.end_position().row as u32 + 1,
                        exported,
                        file: file.to_owned(),
                    });
                }
            }
            "method_declaration" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source);
                    let exported = name.starts_with(char::is_uppercase);
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Function,
                        start_line: child.start_position().row as u32 + 1,
                        end_line: child.end_position().row as u32 + 1,
                        exported,
                        file: file.to_owned(),
                    });
                }
            }
            "type_declaration" => {
                // type_declaration has type_spec children
                let mut inner_cursor = child.walk();
                for spec in child.children(&mut inner_cursor) {
                    if spec.kind() == "type_spec" {
                        if let Some(name_node) = spec.child_by_field_name("name") {
                            let name = node_text(name_node, source);
                            let exported = name.starts_with(char::is_uppercase);
                            symbols.push(Symbol {
                                name,
                                kind: SymbolKind::Type,
                                start_line: spec.start_position().row as u32 + 1,
                                end_line: spec.end_position().row as u32 + 1,
                                exported,
                                file: file.to_owned(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
    symbols
}

fn extract_go_imports(root: Node<'_>, source: &[u8]) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        if child.kind() == "import_declaration" {
            let mut inner_cursor = child.walk();
            for spec_or_list in child.children(&mut inner_cursor) {
                if spec_or_list.kind() == "import_spec" {
                    extract_go_import_spec(spec_or_list, source, &mut imports);
                } else if spec_or_list.kind() == "import_spec_list" {
                    let mut list_cursor = spec_or_list.walk();
                    for spec in spec_or_list.children(&mut list_cursor) {
                        if spec.kind() == "import_spec" {
                            extract_go_import_spec(spec, source, &mut imports);
                        }
                    }
                }
            }
        }
    }
    imports
}

fn extract_go_import_spec(node: Node<'_>, source: &[u8], imports: &mut Vec<ImportInfo>) {
    let mut alias = None;
    let mut path = String::new();

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "package_identifier" => {
                alias = Some(node_text(child, source));
            }
            "interpreted_string_literal" => {
                path = node_text(child, source);
                // Remove quotes
                path = path.trim_matches('"').to_owned();
            }
            _ => {}
        }
    }

    if !path.is_empty() {
        imports.push(ImportInfo {
            path,
            alias,
            names: Vec::new(),
            line: node.start_position().row as u32 + 1,
        });
    }
}

// --- Python symbol extraction ---

fn extract_python_symbols(root: Node<'_>, source: &[u8], file: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        match child.kind() {
            "function_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source);
                    let exported = !name.starts_with('_');
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Function,
                        start_line: child.start_position().row as u32 + 1,
                        end_line: child.end_position().row as u32 + 1,
                        exported,
                        file: file.to_owned(),
                    });
                }
            }
            "class_definition" => {
                if let Some(name_node) = child.child_by_field_name("name") {
                    let name = node_text(name_node, source);
                    let exported = !name.starts_with('_');
                    symbols.push(Symbol {
                        name,
                        kind: SymbolKind::Type,
                        start_line: child.start_position().row as u32 + 1,
                        end_line: child.end_position().row as u32 + 1,
                        exported,
                        file: file.to_owned(),
                    });
                }
            }
            "decorated_definition" => {
                // Look inside for the actual function/class definition
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    match inner.kind() {
                        "function_definition" => {
                            if let Some(name_node) = inner.child_by_field_name("name") {
                                let name = node_text(name_node, source);
                                let exported = !name.starts_with('_');
                                symbols.push(Symbol {
                                    name,
                                    kind: SymbolKind::Function,
                                    start_line: inner.start_position().row as u32 + 1,
                                    end_line: inner.end_position().row as u32 + 1,
                                    exported,
                                    file: file.to_owned(),
                                });
                            }
                        }
                        "class_definition" => {
                            if let Some(name_node) = inner.child_by_field_name("name") {
                                let name = node_text(name_node, source);
                                let exported = !name.starts_with('_');
                                symbols.push(Symbol {
                                    name,
                                    kind: SymbolKind::Type,
                                    start_line: inner.start_position().row as u32 + 1,
                                    end_line: inner.end_position().row as u32 + 1,
                                    exported,
                                    file: file.to_owned(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    symbols
}

fn extract_python_imports(root: Node<'_>, source: &[u8]) -> Vec<ImportInfo> {
    let mut imports = Vec::new();
    let mut cursor = root.walk();

    for child in root.children(&mut cursor) {
        match child.kind() {
            "import_statement" => {
                // import X, import X as Y
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "dotted_name" {
                        imports.push(ImportInfo {
                            path: node_text(inner, source),
                            alias: None,
                            names: Vec::new(),
                            line: child.start_position().row as u32 + 1,
                        });
                    } else if inner.kind() == "aliased_import" {
                        let mut alias_cursor = inner.walk();
                        let mut path = String::new();
                        let mut alias = None;
                        for a in inner.children(&mut alias_cursor) {
                            if a.kind() == "dotted_name" {
                                path = node_text(a, source);
                            } else if a.kind() == "identifier" {
                                alias = Some(node_text(a, source));
                            }
                        }
                        if !path.is_empty() {
                            imports.push(ImportInfo {
                                path,
                                alias,
                                names: Vec::new(),
                                line: child.start_position().row as u32 + 1,
                            });
                        }
                    }
                }
            }
            "import_from_statement" => {
                // from X import Y, Z
                // The module path is the dotted_name/relative_import after "from"
                // and before "import". Imported names come after "import".
                let mut path = String::new();
                let mut names = Vec::new();
                let mut seen_import_keyword = false;
                let mut inner_cursor = child.walk();
                for inner in child.children(&mut inner_cursor) {
                    if inner.kind() == "import" {
                        seen_import_keyword = true;
                    } else if !seen_import_keyword {
                        // Before "import" keyword -- module path.
                        if inner.kind() == "dotted_name" || inner.kind() == "relative_import" {
                            path = node_text(inner, source);
                        }
                    } else {
                        // After "import" keyword -- imported names.
                        if inner.kind() == "aliased_import" {
                            // from X import Y as Z — use Z (the alias) as the local name
                            let mut orig = String::new();
                            let mut alias_name = None;
                            let mut alias_inner = inner.walk();
                            for a in inner.children(&mut alias_inner) {
                                if a.kind() == "dotted_name" || a.kind() == "identifier" {
                                    if orig.is_empty() {
                                        orig = node_text(a, source);
                                    } else {
                                        alias_name = Some(node_text(a, source));
                                    }
                                }
                            }
                            names.push(alias_name.unwrap_or(orig));
                        } else if inner.kind() == "dotted_name" || inner.kind() == "identifier" {
                            names.push(node_text(inner, source));
                        }
                    }
                }
                if !path.is_empty() {
                    imports.push(ImportInfo {
                        path,
                        alias: None,
                        names,
                        line: child.start_position().row as u32 + 1,
                    });
                }
            }
            _ => {}
        }
    }
    imports
}

// --- Identifier collection for reference tracking ---

fn is_import_node(kind: &str) -> bool {
    matches!(
        kind,
        "import_statement"
            | "import_from_statement"
            | "import_declaration"
            | "import_spec"
            | "import_spec_list"
    )
}

fn collect_identifiers(
    node: Node<'_>,
    source: &[u8],
    file: &str,
    language: Language,
    refs: &mut Vec<Reference>,
) {
    if is_import_node(node.kind()) {
        return;
    }

    match node.kind() {
        "identifier" | "type_identifier" | "field_identifier"
            if !is_definition_name(node, language) =>
        {
            refs.push(Reference {
                name: node_text(node, source),
                file: file.to_owned(),
                line: node.start_position().row as u32 + 1,
            });
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_identifiers(child, source, file, language, refs);
    }
}

fn is_definition_name(node: Node<'_>, language: Language) -> bool {
    if let Some(parent) = node.parent() {
        let parent_kind = parent.kind();
        match language {
            Language::Go => {
                if matches!(
                    parent_kind,
                    "function_declaration" | "method_declaration" | "type_spec"
                ) {
                    if let Some(name_node) = parent.child_by_field_name("name") {
                        return name_node.id() == node.id();
                    }
                }
            }
            Language::Python => {
                if matches!(parent_kind, "function_definition" | "class_definition") {
                    if let Some(name_node) = parent.child_by_field_name("name") {
                        return name_node.id() == node.id();
                    }
                }
            }
        }
    }
    false
}

fn node_text(node: Node<'_>, source: &[u8]) -> String {
    node.utf8_text(source).unwrap_or("").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn test_extract_go_functions() {
        let src = b"package main\n\nfunc main() {}\n\nfunc helper() {}\n";
        let tree = parser::parse(src, Language::Go).unwrap();
        let symbols = extract_symbols(&tree, src, Language::Go, "main.go");
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "main");
        assert_eq!(symbols[0].kind, SymbolKind::Function);
        assert!(!symbols[0].exported); // lowercase
        assert_eq!(symbols[1].name, "helper");
    }

    #[test]
    fn test_extract_go_exported() {
        let src = b"package pkg\n\nfunc Public() {}\n\nfunc private() {}\n";
        let tree = parser::parse(src, Language::Go).unwrap();
        let symbols = extract_symbols(&tree, src, Language::Go, "pkg.go");
        let public = symbols.iter().find(|s| s.name == "Public").unwrap();
        let private = symbols.iter().find(|s| s.name == "private").unwrap();
        assert!(public.exported);
        assert!(!private.exported);
    }

    #[test]
    fn test_extract_go_types() {
        let src = b"package main\n\ntype Foo struct {}\n\ntype bar int\n";
        let tree = parser::parse(src, Language::Go).unwrap();
        let symbols = extract_symbols(&tree, src, Language::Go, "main.go");
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].kind, SymbolKind::Type);
        assert!(symbols[0].exported);
        assert!(!symbols[1].exported);
    }

    #[test]
    fn test_extract_go_imports() {
        let src = b"package main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n";
        let tree = parser::parse(src, Language::Go).unwrap();
        let imports = extract_imports(&tree, src, Language::Go);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].path, "fmt");
        assert_eq!(imports[1].path, "os");
    }

    #[test]
    fn test_extract_python_functions() {
        let src = b"def hello():\n    pass\n\ndef _private():\n    pass\n";
        let tree = parser::parse(src, Language::Python).unwrap();
        let symbols = extract_symbols(&tree, src, Language::Python, "app.py");
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].name, "hello");
        assert!(symbols[0].exported);
        assert_eq!(symbols[1].name, "_private");
        assert!(!symbols[1].exported);
    }

    #[test]
    fn test_extract_python_classes() {
        let src = b"class MyClass:\n    def method(self):\n        pass\n";
        let tree = parser::parse(src, Language::Python).unwrap();
        let symbols = extract_symbols(&tree, src, Language::Python, "app.py");
        // Should find the class at top level.
        let class = symbols.iter().find(|s| s.name == "MyClass").unwrap();
        assert_eq!(class.kind, SymbolKind::Type);
        assert!(class.exported);
    }

    #[test]
    fn test_extract_python_imports() {
        let src = b"import os\nfrom pathlib import Path\n";
        let tree = parser::parse(src, Language::Python).unwrap();
        let imports = extract_imports(&tree, src, Language::Python);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].path, "os");
        assert_eq!(imports[1].path, "pathlib");
    }

    #[test]
    fn test_extract_references() {
        let src = b"package main\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n";
        let tree = parser::parse(src, Language::Go).unwrap();
        let refs = extract_references(&tree, src, Language::Go, "main.go");
        let has_fmt = refs.iter().any(|r| r.name == "fmt");
        let has_println = refs.iter().any(|r| r.name == "Println");
        assert!(has_fmt, "should reference fmt");
        assert!(has_println, "should reference Println");
    }
}
