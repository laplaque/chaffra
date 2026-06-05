//! Core types, configuration, and severity model shared across all chaffra crates.
//!
//! This crate defines the foundational abstractions -- diagnostics, severity levels,
//! configuration structs, the `AnalysisModule` trait, the `ModuleHost`, and error
//! types -- that every other chaffra crate depends on.

pub mod config;
pub mod diagnostic;
pub mod error;
pub mod grpc;
pub mod module;
pub mod telemetry;
