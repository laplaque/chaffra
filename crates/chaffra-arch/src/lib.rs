//! Architecture boundary validation.
//!
//! Enforces import rules derived from architectural presets (layered, hexagonal,
//! feature-sliced, clean) or custom zone/rule definitions from `.chaffra.toml`.
//! Reports violations when a package imports across a declared forbidden boundary.
