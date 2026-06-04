//! tree-sitter integration and per-language AST walkers.
//!
//! This crate wraps the `tree-sitter` library to provide a unified interface for
//! parsing source files and traversing language-specific syntax trees. Consumers
//! receive typed AST nodes that higher-level analysis crates can operate on without
//! dealing with raw tree-sitter cursor APIs directly.
