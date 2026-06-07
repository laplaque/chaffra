//! tree-sitter integration and per-language AST walkers.
//!
//! This crate wraps the `tree-sitter` library to provide a unified interface for
//! parsing source files, extracting symbols, building import graphs, and scanning
//! for suppression comments. It supports Go and Python.

use chaffra_core::diagnostic::Language;

pub mod discovery;
pub mod graph;
pub mod parser;
pub mod suppression;
pub mod symbols;

/// Detect language from a file path based on its extension.
pub fn detect_language(path: &str) -> Option<Language> {
    let ext = path.rsplit('.').next()?;
    Language::from_extension(ext)
}
