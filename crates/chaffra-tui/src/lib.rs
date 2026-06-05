//! Terminal UI for browsing and acting on chaffra findings.
//!
//! Provides a list-based interface with keyboard navigation, grouping by file/rule/severity,
//! filtering by severity/module, and actions (apply fix, add suppression, copy location).

pub mod app;
pub mod render;

pub use app::{App, GroupBy, TuiAction};
