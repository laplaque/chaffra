//! Regression tests: the MCP analysis tools must fail closed on a
//! malformed/unreadable `.chaffra.toml`, matching the CLI strict loader.
//!
//! These live in an integration test (separate compilation unit) rather than
//! an inline `#[cfg(test)] mod tests` in `src/tools.rs` on purpose: keeping a
//! large test module inside `tools.rs` perturbs that file's LCOV `SF` record
//! enough to trip the coverage checker's strict `LH >= unique-hit-DA` bound
//! under the CI feature-powerset profraw accumulation (an off-by-one in the
//! `cargo-llvm-cov` merge summary). Exercising the public entry points from
//! here keeps the production fail-closed branches covered without growing the
//! `src/tools.rs` record.

use chaffra_mcp::tools::{execute_dead_code, execute_health};

/// Write a malformed `.chaffra.toml` into a fresh temp dir and return its path.
fn dir_with_malformed_config(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("chaffra_mcp_test_bad_config_{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".chaffra.toml"), "this is = = not valid toml\n").unwrap();
    dir
}

#[test]
fn execute_health_fails_closed_on_malformed_config() {
    // The old `.unwrap_or_default()` silently ran against the default config.
    // A malformed TOML must now surface the typed `ChaffraError::Config` to
    // the caller as a ToolCallResult error.
    let dir = dir_with_malformed_config("health");
    let result = execute_health(&serde_json::json!({ "path": dir.to_str().unwrap() }));
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        result.is_error,
        Some(true),
        "execute_health must fail closed on malformed config, not default"
    );
    assert!(
        result.content[0].text.contains("Invalid configuration"),
        "expected config error, got: {}",
        result.content[0].text
    );
}

#[test]
fn execute_dead_code_fails_closed_on_malformed_config() {
    // Same fail-closed contract for the dead-code MCP tool.
    let dir = dir_with_malformed_config("deadcode");
    let result = execute_dead_code(&serde_json::json!({ "path": dir.to_str().unwrap() }));
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(
        result.is_error,
        Some(true),
        "execute_dead_code must fail closed on malformed config, not default"
    );
    assert!(
        result.content[0].text.contains("Invalid configuration"),
        "expected config error, got: {}",
        result.content[0].text
    );
}
