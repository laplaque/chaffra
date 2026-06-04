//! Cyclomatic and cognitive complexity metrics.
//!
//! Computes per-function complexity scores directly from tree-sitter ASTs.
//! Cyclomatic complexity counts independent control-flow paths; cognitive
//! complexity weights nesting depth to better reflect human comprehension cost.
//! Results feed into health scoring and hotspot ranking.
