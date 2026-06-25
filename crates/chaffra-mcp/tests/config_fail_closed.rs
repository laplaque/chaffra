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

#[test]
fn execute_telemetry_snapshot_is_projected_under_default_user_only() {
    // R4-3: `chaffra/telemetry` action=snapshot must serialize an
    // audience-PROJECTED snapshot, not the raw collector output. The MCP
    // tool runs against a default `TelemetryConfig`, whose audience is
    // `user-only` (Phase 15a.1 privacy default). Under `user-only` the
    // projection drops `operator_summary` (set to the default empty form),
    // all operator-scoped data points, spans, and operator-only definitions.
    // The serialized payload must reflect that — specifically, the
    // operator-summary fields (`module_call_durations`, `module_error_counts`)
    // are empty in the default form, but more importantly the operator
    // metric names registered by `register_core_metrics` (e.g.
    // `chaffra.module.call_duration_ms`) must NOT appear in the serialized
    // `definitions` map.
    let result = execute_telemetry(&serde_json::json!({ "action": "snapshot" }));
    assert!(
        result.is_error.is_none() || result.is_error == Some(false),
        "snapshot returned an error: {}",
        result.content[0].text
    );
    let body = &result.content[0].text;
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("snapshot output must be JSON");

    let definitions = parsed
        .get("definitions")
        .and_then(|d| d.as_object())
        .expect("definitions object present in snapshot JSON");
    // The OPERATOR-scoped definitions registered by `register_core_metrics`
    // must NOT appear in the user-only projected payload. Spot-check the
    // most operator-disclosing one.
    assert!(
        !definitions.contains_key("chaffra.module.call_duration_ms"),
        "operator definition leaked into user-only MCP snapshot: {definitions:?}"
    );
    // The user-facing definitions DO survive — sanity check that projection
    // is "drop operator", not "drop everything".
    assert!(
        definitions.contains_key("chaffra.analysis.findings_total"),
        "user-facing definition was dropped from user-only MCP snapshot: \
         {definitions:?}"
    );
}

#[test]
fn execute_telemetry_status_and_backends_are_gated_under_default_user_only() {
    // R4-1 parallel: `status` (backend connectivity) and `backends` (kind /
    // endpoint / path) are operator-disclosing. Under the default `user-only`
    // audience they must return an empty list rather than leak the
    // configured backend catalogue.
    for action in ["status", "backends"] {
        let result = execute_telemetry(&serde_json::json!({ "action": action }));
        assert!(
            result.is_error.is_none() || result.is_error == Some(false),
            "{action} returned an error: {}",
            result.content[0].text
        );
        let body = result.content[0].text.trim();
        assert_eq!(
            body, "[]",
            "{action} must return [] under default (user-only) audience, got: {body}"
        );
    }
}

#[test]
fn execute_telemetry_ignores_any_caller_supplied_audience_param() {
    // R5-2: an earlier revision (R4-3) accepted an `audience` parameter on
    // this tool so the operator branches were reachable from integration
    // tests; that was a widening attack vector — any MCP client could pass
    // `audience=on` and read operator data the project's `user-only` default
    // would have withheld. The parameter is removed; the MCP entry point
    // ALWAYS runs at the project's resolved audience. Verify the projection
    // remains `user-only` even when the caller attempts to pass
    // `audience=on` / `operator-only` — no operator definitions should leak
    // and the gated `status`/`backends` paths should still return `[]`.
    let definitions_for = |params: &serde_json::Value| {
        let result = execute_telemetry(params);
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
            .collect::<std::collections::BTreeSet<String>>()
    };
    let baseline_defs = definitions_for(&serde_json::json!({ "action": "snapshot" }));
    for attempt in ["on", "operator-only"] {
        let widened =
            definitions_for(&serde_json::json!({ "action": "snapshot", "audience": attempt }));
        assert_eq!(
            widened, baseline_defs,
            "MCP audience='{attempt}' widening attempt altered the definition \
             set; the param must be ignored, not honored"
        );
        assert!(
            !widened.contains("chaffra.module.call_duration_ms"),
            "operator definition leaked under MCP audience='{attempt}' widening: {widened:?}"
        );
    }
    // Status/backends must also stay gated against the widening attempt.
    for action in ["status", "backends"] {
        for attempt in ["on", "operator-only"] {
            let result =
                execute_telemetry(&serde_json::json!({ "action": action, "audience": attempt }));
            assert!(result.is_error.is_none() || result.is_error == Some(false));
            assert_eq!(
                result.content[0].text.trim(),
                "[]",
                "{action} leaked under MCP audience='{attempt}' widening attempt"
            );
        }
    }
}

#[test]
fn execute_telemetry_with_config_status_and_backends_populated_under_operator_audience() {
    // R4-1 parallel (other branch): when the audience includes the operator
    // scope, `status` and `backends` MUST return the configured backend
    // catalogue, not the gated `[]`. Exercised through the crate-public
    // internal helper (R5-2) — external MCP callers cannot reach this branch.
    let config = TelemetryConfig {
        audience: TelemetryAudience::On,
        ..TelemetryConfig::default()
    };
    for action in ["status", "backends"] {
        let result = execute_telemetry_with_config(action, &config);
        assert!(
            result.is_error.is_none() || result.is_error == Some(false),
            "{action} returned an error: {}",
            result.content[0].text
        );
        let body = result.content[0].text.trim();
        assert_ne!(
            body, "[]",
            "{action} under audience=On must NOT be gated, got: {body}"
        );
        let parsed: serde_json::Value =
            serde_json::from_str(body).expect("operator-enabled body must be JSON");
        let arr = parsed
            .as_array()
            .expect("operator-enabled body is an array");
        assert!(
            !arr.is_empty(),
            "{action} under audience=On must include the configured backends"
        );
    }
}

#[test]
fn execute_telemetry_with_config_snapshot_under_operator_audience_includes_operator_defs() {
    // R4-3 projection (other branch): under `audience=On` the snapshot must
    // surface operator definitions registered by `register_core_metrics`.
    // Reached through the crate-public internal helper (R5-2).
    let config = TelemetryConfig {
        audience: TelemetryAudience::On,
        ..TelemetryConfig::default()
    };
    let result = execute_telemetry_with_config("snapshot", &config);
    assert!(
        result.is_error.is_none() || result.is_error == Some(false),
        "snapshot returned an error: {}",
        result.content[0].text
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&result.content[0].text).expect("snapshot JSON");
    let definitions = parsed["definitions"]
        .as_object()
        .expect("definitions object");
    assert!(
        definitions.contains_key("chaffra.module.call_duration_ms"),
        "operator definition missing from audience=On MCP snapshot: \
         {definitions:?}"
    );
}
