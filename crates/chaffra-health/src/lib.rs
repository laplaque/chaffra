//! Composite 0-100 health scoring.
//!
//! Thin wrapper that re-exports health scoring from [`chaffra_complexity`].
//! The health scoring logic lives in the complexity crate since it depends
//! directly on complexity metrics. This crate exists as a stable public API
//! entry point.

pub use chaffra_complexity::{
    FunctionMetrics, analyze_project_health, compute_file_health, compute_file_metrics,
    compute_project_health,
};
pub use chaffra_core::diagnostic::{FileHealthScore, HealthGrade, ProjectHealth};
