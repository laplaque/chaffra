//! Regression tests covering the MCP server's fail-closed and audience-
//! projection contracts:
//! 1. The analysis tools (`chaffra/health`, `chaffra/dead-code`) fail closed
//!    on a malformed/unreadable `.chaffra.toml`, matching the CLI strict
//!    loader.
//! 2. The `chaffra/telemetry` tool projects its snapshot through the
//!    resolved audience before serializing (R4-3) and gates operator-shaped
//!    backend metadata (R4-1's MCP parallel).
//!
//! These live in an integration test (separate compilation unit) rather than
//! an inline `#[cfg(test)] mod tests` in `src/tools.rs` on purpose: keeping a
//! large test module inside `tools.rs` perturbed that file's LCOV `SF` record
//! and surfaced a producer-level off-by-one in the `LH` summary of LLVM's
//! `llvm-cov export` under the CI feature-powerset profraw accumulation.
//! Exercising the public entry points from here keeps the production fail-
//! closed branches covered without growing the `src/tools.rs` record; the
//! coverage checker also tolerates the producer's `LH` undercount now
//! (see `scripts/coverage_check.py::parse_lcov`), so the placement is no
//! longer load-bearing — it's just idiomatic for behaviour tests.

use chaffra_mcp::tools::{
    execute_dead_code, execute_health, execute_telemetry, execute_telemetry_with_config,
};
use chaffra_telemetry::{TelemetryAudience, TelemetryConfig};
use tempfile::TempDir;

/// Write a malformed `.chaffra.toml` into a fresh temp dir.
///
/// Returns a `TempDir` so the directory is removed when the guard drops,
/// even if the test panics. Using `TempDir::new()` (random suffix) instead
/// of a fixed name keeps tests robust under concurrent / sharded execution.
fn dir_with_malformed_config() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    std::fs::write(
        dir.path().join(".chaffra.toml"),
        "this is = = not valid toml\n",
    )
    .expect("write malformed config");
    dir
}

/// Fresh temp dir, optionally containing a `.chaffra.toml` with the given
/// body. `None` => no config file (the project default, `user-only`, applies).
fn dir_with_chaffra_toml(body: Option<&str>) -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    if let Some(b) = body {
        std::fs::write(dir.path().join(".chaffra.toml"), b).expect("write .chaffra.toml");
    }
    dir
}

/// Run `chaffra/telemetry` against a specific project directory.
fn telemetry_in(dir: &TempDir, action: &str) -> chaffra_mcp::protocol::ToolCallResult {
    execute_telemetry(&serde_json::json!({
        "action": action,
        "path": dir.path().to_str().unwrap(),
    }))
}

#[test]
fn execute_health_fails_closed_on_malformed_config() {
    // The old `.unwrap_or_default()` silently ran against the default config.
    // A malformed TOML must now surface the typed `ChaffraError::Config` to
    // the caller as a ToolCallResult error.
    let dir = dir_with_malformed_config();
    let result = execute_health(&serde_json::json!({ "path": dir.path().to_str().unwrap() }));

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
    let dir = dir_with_malformed_config();
    let result = execute_dead_code(&serde_json::json!({ "path": dir.path().to_str().unwrap() }));

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

/// Extract the `definitions` key-set from a telemetry `snapshot` result.
fn snapshot_definition_keys(
    result: &chaffra_mcp::protocol::ToolCallResult,
) -> std::collections::BTreeSet<String> {
    assert!(
        result.is_error.is_none() || result.is_error == Some(false),
        "snapshot returned an error: {}",
        result.content[0].text
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&result.content[0].text).expect("snapshot JSON");
    parsed["definitions"]
        .as_object()
        .expect("definitions object present")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn execute_telemetry_snapshot_is_projected_under_default_user_only() {
    // R4-3: `chaffra/telemetry` action=snapshot serializes an
    // audience-PROJECTED snapshot. A project dir with NO `.chaffra.toml`
    // resolves to the privacy default (`user-only`), under which the
    // operator definitions registered by `register_core_metrics` (e.g.
    // `chaffra.module.call_duration_ms`) must NOT appear, while user-facing
    // definitions survive.
    let dir = dir_with_chaffra_toml(None);
    let defs = snapshot_definition_keys(&telemetry_in(&dir, "snapshot"));
    assert!(
        !defs.contains("chaffra.module.call_duration_ms"),
        "operator definition leaked into user-only MCP snapshot: {defs:?}"
    );
    assert!(
        defs.contains("chaffra.analysis.findings_total"),
        "user-facing definition dropped from user-only MCP snapshot: {defs:?}"
    );
}

#[test]
fn execute_telemetry_status_and_backends_gated_under_default_user_only() {
    // R4-1 parallel: `status` / `backends` are operator-disclosing; under the
    // default `user-only` audience (no project config) they return `[]`.
    let dir = dir_with_chaffra_toml(None);
    for action in ["status", "backends"] {
        let result = telemetry_in(&dir, action);
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        assert_eq!(
            result.content[0].text.trim(),
            "[]",
            "{action} must return [] under default (user-only) audience"
        );
    }
}

#[test]
fn execute_telemetry_honors_project_file_audience_opt_in() {
    // R4-F1: `[modules.telemetry] audience = "on"` in the project's
    // `.chaffra.toml` is an explicit operator opt-in for this MCP surface,
    // resolved through the SAME strict loader as the other tools (no parallel
    // `TelemetryConfig::default()` path). Under the opt-in, `status` /
    // `backends` return the configured backend catalogue and `snapshot`
    // surfaces operator definitions.
    let dir = dir_with_chaffra_toml(Some("[modules.telemetry]\naudience = \"on\"\n"));

    for action in ["status", "backends"] {
        let result = telemetry_in(&dir, action);
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        let body = result.content[0].text.trim();
        assert_ne!(
            body, "[]",
            "{action} under file audience=on must NOT be gated, got: {body}"
        );
        let arr: serde_json::Value = serde_json::from_str(body).expect("JSON array");
        assert!(
            arr.as_array().is_some_and(|a| !a.is_empty()),
            "{action} under file audience=on must include the configured backends"
        );
    }

    let defs = snapshot_definition_keys(&telemetry_in(&dir, "snapshot"));
    assert!(
        defs.contains("chaffra.module.call_duration_ms"),
        "operator definition missing from file-audience=on MCP snapshot: {defs:?}"
    );
}

#[test]
fn execute_telemetry_honors_project_file_audience_operator_only() {
    // R4-F1: `operator-only` is also a valid file opt-in; `status` must
    // surface the backend catalogue.
    let dir = dir_with_chaffra_toml(Some("[modules.telemetry]\naudience = \"operator-only\"\n"));
    let result = telemetry_in(&dir, "status");
    assert!(result.is_error.is_none() || result.is_error == Some(false));
    assert_ne!(
        result.content[0].text.trim(),
        "[]",
        "status under file audience=operator-only must NOT be gated"
    );
}

#[test]
fn execute_telemetry_fails_closed_on_malformed_project_config() {
    // R4-F1: a malformed `.chaffra.toml` must fail closed for this tool too,
    // not silently default — matching `execute_health` / `execute_dead_code`.
    let dir = dir_with_malformed_config();
    let result = telemetry_in(&dir, "snapshot");
    assert_eq!(
        result.is_error,
        Some(true),
        "chaffra/telemetry must fail closed on malformed .chaffra.toml"
    );
    assert!(
        result.content[0].text.contains("Invalid configuration"),
        "expected config error, got: {}",
        result.content[0].text
    );
}

#[test]
fn execute_telemetry_fails_closed_on_invalid_audience_value() {
    // R4-F1: an invalid `[modules.telemetry] audience` value is surfaced as
    // an error (via `from_module_config`), never coerced to a wider default.
    let dir = dir_with_chaffra_toml(Some("[modules.telemetry]\naudience = \"everyone\"\n"));
    let result = telemetry_in(&dir, "snapshot");
    assert_eq!(
        result.is_error,
        Some(true),
        "chaffra/telemetry must fail closed on an invalid audience value"
    );
    assert!(
        result.content[0]
            .text
            .contains("Invalid [modules.telemetry] configuration"),
        "expected telemetry-config error, got: {}",
        result.content[0].text
    );
}

#[test]
fn execute_telemetry_rejects_unresolvable_path() {
    // The `path` param is canonicalized (mirroring `execute_health`); a path
    // that cannot be resolved is surfaced as an error rather than silently
    // falling back to the current directory.
    let result = execute_telemetry(&serde_json::json!({
        "action": "snapshot",
        "path": "/no/such/chaffra/dir/definitely/missing",
    }));
    assert_eq!(
        result.is_error,
        Some(true),
        "chaffra/telemetry must error on an unresolvable path"
    );
    assert!(
        result.content[0].text.contains("Invalid path"),
        "expected path error, got: {}",
        result.content[0].text
    );
}

#[test]
fn execute_telemetry_ignores_caller_supplied_audience_param() {
    // R5-2: the audience is resolved ONLY from the project file, never from
    // request params. A caller passing `audience=on` against a default
    // (user-only) project must NOT widen the output: definitions stay
    // user-only and the gated actions stay `[]`. The param is simply ignored.
    let dir = dir_with_chaffra_toml(None);

    let baseline = snapshot_definition_keys(&telemetry_in(&dir, "snapshot"));
    for attempt in ["on", "operator-only"] {
        let widened = snapshot_definition_keys(&execute_telemetry(&serde_json::json!({
            "action": "snapshot",
            "path": dir.path().to_str().unwrap(),
            "audience": attempt,
        })));
        assert_eq!(
            widened, baseline,
            "MCP audience='{attempt}' request param widened the snapshot; it must be ignored"
        );
        assert!(
            !widened.contains("chaffra.module.call_duration_ms"),
            "operator definition leaked under MCP audience='{attempt}' request param"
        );
    }
    for action in ["status", "backends"] {
        for attempt in ["on", "operator-only"] {
            let result = execute_telemetry(&serde_json::json!({
                "action": action,
                "path": dir.path().to_str().unwrap(),
                "audience": attempt,
            }));
            assert!(result.is_error.is_none() || result.is_error == Some(false));
            assert_eq!(
                result.content[0].text.trim(),
                "[]",
                "{action} leaked under MCP audience='{attempt}' request param"
            );
        }
    }
}

#[test]
fn execute_telemetry_with_config_status_and_backends_populated_under_operator_audience() {
    // The crate-internal helper drives the operator branches directly (used
    // here and reachable only in-crate). Pairs with the file-audience tests
    // above which exercise the same branches through the public entry point.
    let config = TelemetryConfig {
        audience: TelemetryAudience::On,
        ..TelemetryConfig::default()
    };
    for action in ["status", "backends"] {
        let result = execute_telemetry_with_config(action, &config);
        assert!(result.is_error.is_none() || result.is_error == Some(false));
        let body = result.content[0].text.trim();
        assert_ne!(body, "[]", "{action} under audience=On must NOT be gated");
        let arr: serde_json::Value = serde_json::from_str(body).expect("JSON array");
        assert!(arr.as_array().is_some_and(|a| !a.is_empty()));
    }
}
