//! Import graph construction and traversal.

use crate::symbols::{ImportInfo, Reference, Symbol};
use std::collections::{HashMap, HashSet};

/// A node in the import/reference graph.
#[derive(Debug, Clone)]
pub struct GraphNode {
    /// File path.
    pub file: String,
    /// Symbols defined in this file.
    pub symbols: Vec<Symbol>,
    /// Imports in this file.
    pub imports: Vec<ImportInfo>,
    /// References from this file to other symbols.
    pub references: Vec<Reference>,
}

/// An import/reference graph across all analyzed files.
#[derive(Debug, Default)]
pub struct ImportGraph {
    /// Nodes keyed by file path.
    pub nodes: HashMap<String, GraphNode>,
}

impl ImportGraph {
    /// Create a new empty graph.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Add a file's symbols, imports, and references to the graph.
    pub fn add_file(
        &mut self,
        file: &str,
        symbols: Vec<Symbol>,
        imports: Vec<ImportInfo>,
        references: Vec<Reference>,
    ) {
        self.nodes.insert(
            file.to_owned(),
            GraphNode {
                file: file.to_owned(),
                symbols,
                imports,
                references,
            },
        );
    }

    /// Get all symbol names defined across all files.
    pub fn all_symbols(&self) -> Vec<&Symbol> {
        self.nodes.values().flat_map(|n| &n.symbols).collect()
    }

    /// Get all symbol names referenced across all files.
    pub fn all_references(&self) -> HashSet<String> {
        self.nodes
            .values()
            .flat_map(|n| n.references.iter().map(|r| r.name.clone()))
            .collect()
    }

    /// Find all files that reference a given symbol name.
    pub fn files_referencing(&self, symbol_name: &str) -> Vec<String> {
        self.nodes
            .values()
            .filter(|n| n.references.iter().any(|r| r.name == symbol_name))
            .map(|n| n.file.clone())
            .collect()
    }

    /// Find symbols that are never referenced by any other file.
    pub fn unreferenced_symbols(&self) -> Vec<&Symbol> {
        let all_refs = self.all_references();
        self.all_symbols()
            .into_iter()
            .filter(|s| !all_refs.contains(&s.name))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::SymbolKind;

    fn sym(name: &str, file: &str, kind: SymbolKind) -> Symbol {
        Symbol {
            name: name.to_owned(),
            kind,
            start_line: 1,
            end_line: 1,
            exported: true,
            file: file.to_owned(),
        }
    }

    fn reference(name: &str, file: &str) -> Reference {
        Reference {
            name: name.to_owned(),
            file: file.to_owned(),
            line: 1,
        }
    }

    #[test]
    fn test_graph_unreferenced() {
        let mut graph = ImportGraph::new();
        graph.add_file(
            "a.go",
            vec![
                sym("Used", "a.go", SymbolKind::Function),
                sym("Unused", "a.go", SymbolKind::Function),
            ],
            vec![],
            vec![],
        );
        graph.add_file("b.go", vec![], vec![], vec![reference("Used", "b.go")]);

        let unreferenced = graph.unreferenced_symbols();
        assert_eq!(unreferenced.len(), 1);
        assert_eq!(unreferenced[0].name, "Unused");
    }

    #[test]
    fn test_graph_files_referencing() {
        let mut graph = ImportGraph::new();
        graph.add_file("a.go", vec![], vec![], vec![reference("Foo", "a.go")]);
        graph.add_file("b.go", vec![], vec![], vec![reference("Foo", "b.go")]);
        graph.add_file("c.go", vec![], vec![], vec![]);

        let files = graph.files_referencing("Foo");
        assert_eq!(files.len(), 2);
    }
}
