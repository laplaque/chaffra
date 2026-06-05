// TODO(#19): coverage gate unenforceable until CI tooling lands

//! Model Context Protocol (MCP) server.
//!
//! Exposes chaffra analysis capabilities as MCP tools so that AI coding assistants
//! (Claude, Copilot, Cursor, etc.) can query health scores, dead-code findings,
//! hotspots, and architecture violations directly from their context window.
//!
//! Implements JSON-RPC 2.0 over stdio as specified by the MCP protocol.

pub mod protocol;
pub mod server;
pub mod tools;

pub use server::McpServer;
