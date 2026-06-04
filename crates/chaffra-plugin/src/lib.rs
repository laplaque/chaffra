//! gRPC plugin host and protocol definitions.
//!
//! Defines the Protobuf service contract and hosts third-party framework plugins
//! that extend chaffra's language/framework awareness (e.g., gin, FastAPI). Plugins
//! run as separate processes or containers and communicate over a local gRPC channel.

pub mod client;
pub mod config;
pub mod error;
pub mod host;
pub mod proto;
