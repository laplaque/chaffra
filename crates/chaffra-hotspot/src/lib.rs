//! Hotspot ranking by churn × complexity.
//!
//! Combines git commit history (read via `gix`) with per-file complexity scores
//! to surface files that are both frequently modified and structurally complex.
//! These hotspots carry the highest maintenance risk and deserve refactoring priority.
