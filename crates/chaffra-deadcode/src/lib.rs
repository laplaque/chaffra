//! Dead code detection engine.
//!
//! Identifies unreachable or unused symbols — functions, types, imports, and entire
//! files — by building a reference graph from parsed ASTs and finding nodes with no
//! live path from a declared entry point. Supports configurable severity per rule.
