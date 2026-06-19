//! Deterministic seeded telemetry data for dev, tests, and demo mode.
//!
//! Produces a `LiveTelemetryState` pre-populated with realistic but
//! reproducible snapshots spanning a simulated 7-day window.

use crate::collector::{ModuleSummary, OperatorSummary, TelemetrySnapshot, UserSummary};
use crate::live_state::{LiveTelemetryState, StateSource};
use crate::metrics::{MetricDataPoint, MetricDefinition, MetricKind};
use std::collections::HashMap;

/// Deterministic base timestamp (fixed, not wall-clock dependent).
const BASE_TS: u64 = 1_718_000_000_000;

/// Interval between historical snapshots (15 hours in milliseconds).
/// 12 snapshots x 11 intervals x 54M ms = 594M ms < 604.8M ms (7 days),
/// so all snapshots fit within a 7-day query window.
const SNAPSHOT_INTERVAL: u64 = 54_000_000;

/// Build a `LiveTelemetryState` pre-loaded with deterministic demo data.
///
/// Includes:
/// - 3+ modules with varying health scores
/// - Findings across 3+ severities and 2+ modules
/// - New, resolved, and unchanged finding churn
/// - Module call durations with one intentionally slow module (security=850ms)
/// - At least one module error (security, on odd iterations)
/// - At least one telemetry backend connectivity warning (OTLP, on iteration 3)
/// - Cache hit/miss metrics
/// - 12 historical snapshots spaced 15 hours apart over a simulated 7-day window
pub fn seed_live_state() -> LiveTelemetryState {
    let state = LiveTelemetryState::new();

    for i in 0..12 {
        let ts = BASE_TS + i * SNAPSHOT_INTERVAL;
        let snapshot = build_seeded_snapshot(ts, i);
        state.push_seeded(snapshot);
    }

    state.set_source(StateSource::Seeded);
    state
}

fn build_seeded_snapshot(ts: u64, iteration: u64) -> TelemetrySnapshot {
    // --- Module summaries ---
    let mut module_summaries = HashMap::new();
    let mut module_call_durations = HashMap::new();
    let mut module_error_counts = HashMap::new();
    let mut findings_by_module = HashMap::new();

    // dead-code: health 92, fast, findings mostly warnings
    let dc_findings = 3 + (iteration % 3);
    module_summaries.insert(
        "dead-code".to_owned(),
        ModuleSummary {
            duration_ms: 45 + iteration * 2,
            finding_count: dc_findings,
            metrics: {
                let mut m = HashMap::new();
                m.insert("health_score".to_owned(), 92.0);
                m.insert("unused_functions".to_owned(), dc_findings as f64);
                m
            },
        },
    );
    module_call_durations.insert("dead-code".to_owned(), 45 + iteration * 2);
    findings_by_module.insert("dead-code".to_owned(), dc_findings);

    // complexity: health 78, moderate speed, warnings + info
    let cx_findings = 5 + (iteration % 4);
    module_summaries.insert(
        "complexity".to_owned(),
        ModuleSummary {
            duration_ms: 62 + iteration * 3,
            finding_count: cx_findings,
            metrics: {
                let mut m = HashMap::new();
                m.insert("health_score".to_owned(), 78.0);
                m.insert("cyclomatic_avg".to_owned(), 6.2);
                m.insert("cognitive_avg".to_owned(), 4.8);
                m
            },
        },
    );
    module_call_durations.insert("complexity".to_owned(), 62 + iteration * 3);
    findings_by_module.insert("complexity".to_owned(), cx_findings);

    // security: health 65, intentionally SLOW (850ms), errors + warnings + info
    let sec_findings = 4 + (iteration % 2);
    module_summaries.insert(
        "security".to_owned(),
        ModuleSummary {
            duration_ms: 850,
            finding_count: sec_findings,
            metrics: {
                let mut m = HashMap::new();
                m.insert("health_score".to_owned(), 65.0);
                m.insert("cve_count".to_owned(), 2.0);
                m
            },
        },
    );
    module_call_durations.insert("security".to_owned(), 850);
    findings_by_module.insert("security".to_owned(), sec_findings);

    // Per-module severity distribution
    // dead-code: all warnings
    let mut module_severities: HashMap<String, HashMap<String, u64>> = HashMap::new();
    module_severities.insert(
        "dead-code".to_owned(),
        [("warning".to_owned(), dc_findings)].into_iter().collect(),
    );
    // complexity: mix of warnings and info
    let cx_warnings = cx_findings / 2;
    let cx_info = cx_findings - cx_warnings;
    module_severities.insert(
        "complexity".to_owned(),
        [
            ("warning".to_owned(), cx_warnings),
            ("info".to_owned(), cx_info),
        ]
        .into_iter()
        .collect(),
    );
    // security: errors, warnings, and info
    let sec_errors = 1 + (iteration % 2);
    let sec_warnings = sec_findings.saturating_sub(sec_errors + 1);
    let sec_info = sec_findings.saturating_sub(sec_errors + sec_warnings);
    module_severities.insert(
        "security".to_owned(),
        [
            ("error".to_owned(), sec_errors),
            ("warning".to_owned(), sec_warnings),
            ("info".to_owned(), sec_info),
        ]
        .into_iter()
        .collect(),
    );

    // Aggregate severity totals from per-module counts
    let mut findings_by_severity = HashMap::new();
    for per_sev in module_severities.values() {
        for (sev, count) in per_sev {
            *findings_by_severity.entry(sev.clone()).or_insert(0u64) += count;
        }
    }
    // Module error: security has an error on every other iteration
    if iteration % 2 == 1 {
        module_error_counts.insert("security".to_owned(), 1);
    }

    let total_findings = dc_findings + cx_findings + sec_findings;

    // --- Data points ---
    let mut data_points = Vec::new();

    // Emit chaffra.module.error_total data points for any module errors
    let mut sorted_error_modules: Vec<_> = module_error_counts.keys().cloned().collect();
    sorted_error_modules.sort();
    for module in &sorted_error_modules {
        let count = module_error_counts[module];
        data_points.push(MetricDataPoint {
            name: "chaffra.module.error_total".to_owned(),
            value: count as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module.clone());
                m
            },
            timestamp_ms: ts,
            user_scoped: false,
        });
    }

    // Per-module call durations (sorted for deterministic order)
    let mut sorted_modules: Vec<_> = module_call_durations.keys().cloned().collect();
    sorted_modules.sort();
    for module in &sorted_modules {
        let dur = module_call_durations[module];
        data_points.push(MetricDataPoint {
            name: "chaffra.module.call_duration_ms".to_owned(),
            value: dur as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module.clone());
                m
            },
            timestamp_ms: ts,
            user_scoped: false,
        });
    }

    // Per-module findings (sorted for deterministic order)
    for module in &sorted_modules {
        let count = findings_by_module[module];
        data_points.push(MetricDataPoint {
            name: "chaffra.analysis.findings_total".to_owned(),
            value: count as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module.clone());
                m
            },
            timestamp_ms: ts,
            user_scoped: true,
        });
    }

    // Per-module, per-severity findings (sorted, using per-module counts)
    let mut all_severities: Vec<_> = findings_by_severity.keys().cloned().collect();
    all_severities.sort();
    for module in &sorted_modules {
        let empty = HashMap::new();
        let mod_sevs = module_severities.get(module).unwrap_or(&empty);
        for severity in &all_severities {
            let count = mod_sevs.get(severity).copied().unwrap_or(0);
            if count > 0 {
                data_points.push(MetricDataPoint {
                    name: "chaffra.analysis.findings_by_severity".to_owned(),
                    value: count as f64,
                    labels: {
                        let mut m = HashMap::new();
                        m.insert("module".to_owned(), module.clone());
                        m.insert("severity".to_owned(), severity.clone());
                        m
                    },
                    timestamp_ms: ts,
                    user_scoped: true,
                });
            }
        }
    }

    // Finding churn (simulated)
    let new_findings = 1 + (iteration % 3);
    let resolved_findings = iteration % 2;
    let unchanged_findings = total_findings.saturating_sub(new_findings);
    let churn_rate = if new_findings + unchanged_findings > 0 {
        new_findings as f64 / (new_findings + unchanged_findings) as f64
    } else {
        0.0
    };

    data_points.push(MetricDataPoint {
        name: "chaffra.findings.new".to_owned(),
        value: new_findings as f64,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.findings.resolved".to_owned(),
        value: resolved_findings as f64,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.findings.unchanged".to_owned(),
        value: unchanged_findings as f64,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.findings.churn_rate".to_owned(),
        value: churn_rate,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });

    // Health scores as data points (for the /health endpoint)
    data_points.push(MetricDataPoint {
        name: "chaffra.module.dead-code.health_score".to_owned(),
        value: 92.0,
        labels: {
            let mut m = HashMap::new();
            m.insert("module".to_owned(), "dead-code".to_owned());
            m
        },
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.module.complexity.health_score".to_owned(),
        value: 78.0,
        labels: {
            let mut m = HashMap::new();
            m.insert("module".to_owned(), "complexity".to_owned());
            m
        },
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.module.security.health_score".to_owned(),
        value: 65.0,
        labels: {
            let mut m = HashMap::new();
            m.insert("module".to_owned(), "security".to_owned());
            m
        },
        timestamp_ms: ts,
        user_scoped: true,
    });

    // Cache metrics
    let cache_hits = 120 + iteration * 10;
    let cache_misses = 30 + iteration * 2;
    data_points.push(MetricDataPoint {
        name: "chaffra.parse.cache_hits".to_owned(),
        value: cache_hits as f64,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.parse.cache_misses".to_owned(),
        value: cache_misses as f64,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });
    data_points.push(MetricDataPoint {
        name: "chaffra.parse.cache_hit_rate".to_owned(),
        value: cache_hits as f64 / (cache_hits + cache_misses) as f64,
        labels: HashMap::new(),
        timestamp_ms: ts,
        user_scoped: true,
    });

    // Backend connectivity warning (on iteration 3)
    if iteration == 3 {
        data_points.push(MetricDataPoint {
            name: "chaffra.backend.connect_error_total".to_owned(),
            value: 1.0,
            labels: {
                let mut m = HashMap::new();
                m.insert("backend".to_owned(), "otlp".to_owned());
                m.insert("endpoint".to_owned(), "localhost:4317".to_owned());
                m
            },
            timestamp_ms: ts,
            user_scoped: false,
        });
    }

    // Module load error (on iteration 5)
    if iteration == 5 {
        data_points.push(MetricDataPoint {
            name: "chaffra.module.load_error_total".to_owned(),
            value: 1.0,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), "hotspot".to_owned());
                m.insert("error_type".to_owned(), "git_not_available".to_owned());
                m
            },
            timestamp_ms: ts,
            user_scoped: false,
        });
    }

    // --- Definitions (registered once, same for all snapshots) ---
    let definitions = core_definitions();

    let total_duration = module_call_durations.values().sum::<u64>();

    TelemetrySnapshot {
        timestamp_ms: ts,
        definitions,
        data_points,
        spans: Vec::new(),
        user_summary: UserSummary {
            analysis_duration_ms: total_duration,
            files_total: 87,
            findings_by_severity,
            findings_by_module,
            module_summaries,
        },
        operator_summary: OperatorSummary {
            module_call_durations,
            module_error_counts,
        },
    }
}

// TODO(#47): derive definitions from the canonical register_core_metrics() registry
// to prevent drift when metric names or kinds change.
fn core_definitions() -> HashMap<String, MetricDefinition> {
    let defs = vec![
        (
            "chaffra.analysis.duration_ms",
            MetricKind::Histogram,
            "Total analysis duration",
        ),
        (
            "chaffra.analysis.files_total",
            MetricKind::Counter,
            "Total files analyzed",
        ),
        (
            "chaffra.analysis.findings_total",
            MetricKind::Counter,
            "Total findings per module",
        ),
        (
            "chaffra.analysis.findings_by_severity",
            MetricKind::Counter,
            "Findings per module and severity",
        ),
        (
            "chaffra.module.call_duration_ms",
            MetricKind::Histogram,
            "Per-module call duration",
        ),
        (
            "chaffra.module.error_total",
            MetricKind::Counter,
            "Per-module error count",
        ),
        (
            "chaffra.module.load_error_total",
            MetricKind::Counter,
            "Module load failures",
        ),
        (
            "chaffra.plugin.connect_error_total",
            MetricKind::Counter,
            "External module gRPC connection failures",
        ),
        (
            "chaffra.backend.connect_error_total",
            MetricKind::Counter,
            "Telemetry backend connectivity failures",
        ),
        (
            "chaffra.findings.new",
            MetricKind::Counter,
            "Findings not in previous run",
        ),
        (
            "chaffra.findings.resolved",
            MetricKind::Counter,
            "Findings in previous run but not current",
        ),
        (
            "chaffra.findings.unchanged",
            MetricKind::Counter,
            "Findings present in both runs",
        ),
        (
            "chaffra.findings.churn_rate",
            MetricKind::Gauge,
            "Churn rate",
        ),
        (
            "chaffra.parse.cache_hits",
            MetricKind::Counter,
            "Parse cache hits",
        ),
        (
            "chaffra.parse.cache_misses",
            MetricKind::Counter,
            "Parse cache misses",
        ),
        (
            "chaffra.parse.cache_hit_rate",
            MetricKind::Gauge,
            "Parse cache hit rate",
        ),
    ];

    defs.into_iter()
        .map(|(name, kind, desc)| {
            (
                name.to_owned(),
                MetricDefinition {
                    name: name.to_owned(),
                    kind,
                    description: desc.to_owned(),
                    unit: "".to_owned(),
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_has_required_modules() {
        let state = seed_live_state();
        assert_eq!(state.source(), StateSource::Seeded);

        let current = state.current().expect("should have a current snapshot");

        // 3+ modules
        assert!(
            current.user_summary.module_summaries.len() >= 3,
            "expected 3+ modules, got {}",
            current.user_summary.module_summaries.len()
        );
        assert!(
            current
                .user_summary
                .module_summaries
                .contains_key("dead-code")
        );
        assert!(
            current
                .user_summary
                .module_summaries
                .contains_key("complexity")
        );
        assert!(
            current
                .user_summary
                .module_summaries
                .contains_key("security")
        );
    }

    #[test]
    fn test_seed_has_different_health_scores() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        let dc_score = current.user_summary.module_summaries["dead-code"].metrics["health_score"];
        let cx_score = current.user_summary.module_summaries["complexity"].metrics["health_score"];
        let sec_score = current.user_summary.module_summaries["security"].metrics["health_score"];

        assert!((dc_score - 92.0).abs() < f64::EPSILON);
        assert!((cx_score - 78.0).abs() < f64::EPSILON);
        assert!((sec_score - 65.0).abs() < f64::EPSILON);
        // All different
        assert_ne!(dc_score as u64, cx_score as u64);
        assert_ne!(cx_score as u64, sec_score as u64);
    }

    #[test]
    fn test_seed_has_three_severities() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        assert!(
            current.user_summary.findings_by_severity.len() >= 3,
            "expected 3+ severities, got {:?}",
            current.user_summary.findings_by_severity
        );
        assert!(
            current
                .user_summary
                .findings_by_severity
                .contains_key("error")
        );
        assert!(
            current
                .user_summary
                .findings_by_severity
                .contains_key("warning")
        );
        assert!(
            current
                .user_summary
                .findings_by_severity
                .contains_key("info")
        );
    }

    #[test]
    fn test_seed_has_finding_churn() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        let has_new = current
            .data_points
            .iter()
            .any(|p| p.name == "chaffra.findings.new");
        let has_resolved = current
            .data_points
            .iter()
            .any(|p| p.name == "chaffra.findings.resolved");
        let has_unchanged = current
            .data_points
            .iter()
            .any(|p| p.name == "chaffra.findings.unchanged");
        let has_churn_rate = current
            .data_points
            .iter()
            .any(|p| p.name == "chaffra.findings.churn_rate");

        assert!(has_new, "should have churn:new");
        assert!(has_resolved, "should have churn:resolved");
        assert!(has_unchanged, "should have churn:unchanged");
        assert!(has_churn_rate, "should have churn:churn_rate");
    }

    #[test]
    fn test_seed_has_slow_module() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        let security_duration = current
            .operator_summary
            .module_call_durations
            .get("security")
            .copied()
            .unwrap_or(0);
        assert_eq!(
            security_duration, 850,
            "security should be the slow module at 850ms"
        );

        // Other modules should be fast (<100ms)
        for (module, &duration) in &current.operator_summary.module_call_durations {
            if module != "security" {
                assert!(
                    duration < 100,
                    "{module} should be fast (<100ms), got {duration}ms"
                );
            }
        }
    }

    #[test]
    fn test_seed_has_module_error() {
        let state = seed_live_state();
        // Check that at least one snapshot has a module error
        let history = state.history_window("7d");
        let has_error = history
            .iter()
            .any(|s| !s.operator_summary.module_error_counts.is_empty());
        assert!(
            has_error,
            "should have at least one snapshot with module errors"
        );
    }

    #[test]
    fn test_seed_has_backend_warning() {
        let state = seed_live_state();
        let history = state.history_window("7d");
        let has_connect_error = history.iter().any(|s| {
            s.data_points
                .iter()
                .any(|p| p.name == "chaffra.backend.connect_error_total")
        });
        assert!(
            has_connect_error,
            "should have at least one backend connectivity warning"
        );
    }

    #[test]
    fn test_seed_has_cache_metrics() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        let has_hits = current
            .data_points
            .iter()
            .any(|p| p.name == "chaffra.parse.cache_hits");
        let has_misses = current
            .data_points
            .iter()
            .any(|p| p.name == "chaffra.parse.cache_misses");
        assert!(has_hits, "should have cache hit metrics");
        assert!(has_misses, "should have cache miss metrics");
    }

    #[test]
    fn test_seed_has_enough_history() {
        let state = seed_live_state();
        assert!(
            state.snapshot_count() >= 10,
            "expected 10+ historical snapshots, got {}",
            state.snapshot_count()
        );
    }

    #[test]
    fn test_seed_timestamps_are_deterministic() {
        let state1 = seed_live_state();
        let state2 = seed_live_state();

        let hist1 = state1.history_window("7d");
        let hist2 = state2.history_window("7d");

        assert_eq!(hist1.len(), hist2.len());
        for (s1, s2) in hist1.iter().zip(hist2.iter()) {
            assert_eq!(s1.timestamp_ms, s2.timestamp_ms);
        }
    }

    #[test]
    fn test_seed_uses_base_timestamp() {
        let state = seed_live_state();
        // Use an unrecognized window to get all history (no filtering)
        let history = state.history_window("all");
        assert_eq!(history[0].timestamp_ms, BASE_TS);
    }

    #[test]
    fn test_seed_findings_across_multiple_modules() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        let modules_with_findings: Vec<_> = current
            .user_summary
            .findings_by_module
            .iter()
            .filter(|(_, count)| **count > 0)
            .collect();
        assert!(
            modules_with_findings.len() >= 2,
            "expected findings across 2+ modules, got {}",
            modules_with_findings.len()
        );
    }

    #[test]
    fn test_seed_per_module_severity_counts_match_finding_totals() {
        let state = seed_live_state();
        let current = state.current().unwrap();

        let severity_dps: Vec<_> = current
            .data_points
            .iter()
            .filter(|p| p.name == "chaffra.analysis.findings_by_severity")
            .collect();

        assert!(
            !severity_dps.is_empty(),
            "expected findings_by_severity datapoints"
        );

        let mut module_severity_totals: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        for dp in &severity_dps {
            let module = dp.labels.get("module").expect("missing module label");
            *module_severity_totals.entry(module.clone()).or_insert(0) += dp.value as u64;
        }

        for (module, expected_count) in &current.user_summary.findings_by_module {
            let severity_total = module_severity_totals.get(module).copied().unwrap_or(0);
            assert_eq!(
                severity_total, *expected_count,
                "module {module}: severity total ({severity_total}) should equal finding count ({expected_count})"
            );
        }

        assert!(
            module_severity_totals.contains_key("security"),
            "security module should have severity datapoints"
        );
        let sec_severities: Vec<_> = severity_dps
            .iter()
            .filter(|dp| dp.labels.get("module").map(|m| m.as_str()) == Some("security"))
            .collect();
        let has_error = sec_severities
            .iter()
            .any(|dp| dp.labels.get("severity").map(|s| s.as_str()) == Some("error"));
        assert!(
            has_error,
            "security module should have error-severity findings"
        );
    }
}
