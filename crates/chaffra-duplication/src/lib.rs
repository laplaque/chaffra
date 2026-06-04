//! Clone detection with four sensitivity modes.
//!
//! Identifies duplicate code blocks using a suffix-tree algorithm. Supports
//! `strict`, `mild`, `weak`, and `semantic` modes so teams can tune how
//! aggressively near-copies and structurally equivalent blocks are reported.
