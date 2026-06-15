//! Live telemetry state: thread-safe shared store with bounded history.
//!
//! Maintains the latest `TelemetrySnapshot` and a circular buffer of historical
//! snapshots, queryable by time window and dimension (module, severity, metric).

use crate::collector::TelemetrySnapshot;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

/// Tracks how the live state was populated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateSource {
    /// Populated from real analysis runs.
    Live,
    /// Populated with deterministic demo/test data.
    Seeded,
    /// No data has been pushed yet.
    Empty,
}

/// Default capacity for the circular history buffer.
const DEFAULT_MAX_HISTORY: usize = 1000;

/// Thread-safe live telemetry state store.
///
/// Holds the latest snapshot and a bounded history buffer. Uses `std::sync::RwLock`
/// so it can be shared across both sync and async contexts.
#[derive(Debug, Clone)]
pub struct LiveTelemetryState {
    inner: Arc<RwLock<StateInner>>,
}

#[derive(Debug)]
struct StateInner {
    source: StateSource,
    current: Option<TelemetrySnapshot>,
    history: VecDeque<TelemetrySnapshot>,
    max_history: usize,
}

/// Window durations in milliseconds.
fn parse_window_ms(window: &str) -> Option<u64> {
    match window {
        "1h" => Some(3_600_000),
        "24h" => Some(86_400_000),
        "7d" => Some(604_800_000),
        _ => None,
    }
}

impl LiveTelemetryState {
    /// Create a new empty live state with default capacity (1000 snapshots).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_HISTORY)
    }

    /// Create a new empty live state with the given history capacity.
    pub fn with_capacity(max: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateInner {
                source: StateSource::Empty,
                current: None,
                history: VecDeque::with_capacity(max),
                max_history: max,
            })),
        }
    }

    /// Push a new snapshot. Updates `current` and appends to history.
    /// If the history buffer is full, the oldest snapshot is evicted.
    pub fn push_snapshot(&self, snapshot: TelemetrySnapshot) {
        let mut inner = self.inner.write().unwrap();
        inner.current = Some(snapshot.clone());
        if inner.history.len() >= inner.max_history {
            inner.history.pop_front();
        }
        inner.history.push_back(snapshot);
        if inner.source != StateSource::Live {
            inner.source = StateSource::Live;
        }
    }

    /// Push a snapshot without changing the source (used for seeded data).
    pub fn push_seeded(&self, snapshot: TelemetrySnapshot) {
        let mut inner = self.inner.write().unwrap();
        inner.current = Some(snapshot.clone());
        if inner.history.len() >= inner.max_history {
            inner.history.pop_front();
        }
        inner.history.push_back(snapshot);
    }

    /// Get the latest snapshot, if any.
    pub fn current(&self) -> Option<TelemetrySnapshot> {
        let inner = self.inner.read().unwrap();
        inner.current.clone()
    }

    /// Get the current state source.
    pub fn source(&self) -> StateSource {
        let inner = self.inner.read().unwrap();
        inner.source
    }

    /// Set the state source (e.g. to `Seeded` after loading demo data).
    pub fn set_source(&self, source: StateSource) {
        let mut inner = self.inner.write().unwrap();
        inner.source = source;
    }

    /// Query history snapshots within a time window.
    ///
    /// Supported windows: `"1h"`, `"24h"`, `"7d"`.
    /// Returns snapshots whose `timestamp_ms` falls within `[latest - window, latest]`.
    /// If the window string is unrecognized, returns all history.
    pub fn history_window(&self, window: &str) -> Vec<TelemetrySnapshot> {
        let inner = self.inner.read().unwrap();
        let Some(window_ms) = parse_window_ms(window) else {
            return inner.history.iter().cloned().collect();
        };

        let latest_ts = inner.current.as_ref().map(|s| s.timestamp_ms).unwrap_or(0);
        let cutoff = latest_ts.saturating_sub(window_ms);

        inner
            .history
            .iter()
            .filter(|s| s.timestamp_ms >= cutoff)
            .cloned()
            .collect()
    }

    /// Query history snapshots that contain data for a specific module within a time window.
    ///
    /// A snapshot "has data for" a module if:
    /// - `user_summary.module_summaries` contains the module, or
    /// - `operator_summary.module_call_durations` contains the module.
    pub fn history_by_module(&self, module: &str, window: &str) -> Vec<TelemetrySnapshot> {
        self.history_window(window)
            .into_iter()
            .filter(|s| {
                s.user_summary.module_summaries.contains_key(module)
                    || s.operator_summary
                        .module_call_durations
                        .contains_key(module)
            })
            .collect()
    }

    /// Clear all state, resetting to `Empty`.
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.source = StateSource::Empty;
        inner.current = None;
        inner.history.clear();
    }

    /// Number of snapshots in the history buffer.
    pub fn snapshot_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.history.len()
    }
}

impl Default for LiveTelemetryState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::{ModuleSummary, OperatorSummary, TelemetrySnapshot, UserSummary};
    use std::collections::HashMap;

    fn make_snapshot(ts: u64, modules: &[&str]) -> TelemetrySnapshot {
        let mut module_summaries = HashMap::new();
        let mut module_call_durations = HashMap::new();
        for &m in modules {
            module_summaries.insert(
                m.to_owned(),
                ModuleSummary {
                    duration_ms: 50,
                    finding_count: 2,
                    metrics: HashMap::new(),
                },
            );
            module_call_durations.insert(m.to_owned(), 50);
        }

        TelemetrySnapshot {
            timestamp_ms: ts,
            definitions: HashMap::new(),
            data_points: Vec::new(),
            spans: Vec::new(),
            user_summary: UserSummary {
                analysis_duration_ms: 100,
                files_total: 10,
                findings_by_severity: HashMap::new(),
                findings_by_module: HashMap::new(),
                module_summaries,
            },
            operator_summary: OperatorSummary {
                module_call_durations,
                module_error_counts: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_new_state_is_empty() {
        let state = LiveTelemetryState::new();
        assert_eq!(state.source(), StateSource::Empty);
        assert!(state.current().is_none());
        assert_eq!(state.snapshot_count(), 0);
    }

    #[test]
    fn test_push_and_current() {
        let state = LiveTelemetryState::new();
        let snap = make_snapshot(1000, &["dead-code"]);
        state.push_snapshot(snap.clone());

        assert_eq!(state.source(), StateSource::Live);
        assert!(state.current().is_some());
        assert_eq!(state.current().unwrap().timestamp_ms, 1000);
        assert_eq!(state.snapshot_count(), 1);
    }

    #[test]
    fn test_push_updates_current() {
        let state = LiveTelemetryState::new();
        state.push_snapshot(make_snapshot(1000, &["dead-code"]));
        state.push_snapshot(make_snapshot(2000, &["complexity"]));

        assert_eq!(state.current().unwrap().timestamp_ms, 2000);
        assert_eq!(state.snapshot_count(), 2);
    }

    #[test]
    fn test_capacity_bounds() {
        let state = LiveTelemetryState::with_capacity(3);
        for i in 0..5 {
            state.push_snapshot(make_snapshot(i * 1000, &["mod"]));
        }

        assert_eq!(state.snapshot_count(), 3);
        // Oldest two were evicted, so first remaining is ts=2000
        let history = state.history_window("7d");
        assert_eq!(history[0].timestamp_ms, 2000);
        assert_eq!(history[2].timestamp_ms, 4000);
    }

    #[test]
    fn test_window_filtering() {
        let state = LiveTelemetryState::new();
        let base = 1_000_000_000_000u64;
        // Push snapshots over a wide range:
        // snap0: base (old, >7d before latest)
        // snap1: base + 604_000_000 (~6.99 days after base)
        // snap2: base + 604_800_000 (exactly 7 days after base) -- latest
        state.push_snapshot(make_snapshot(base, &["a"]));
        state.push_snapshot(make_snapshot(base + 604_000_000, &["a"]));
        state.push_snapshot(make_snapshot(base + 604_800_000, &["a"]));

        // 1h window: cutoff = latest - 3_600_000 = base + 601_200_000
        // snap1 (604_000_000) and snap2 (604_800_000) are both above cutoff
        let one_hour = state.history_window("1h");
        assert_eq!(one_hour.len(), 2);

        // 24h window: cutoff = latest - 86_400_000 = base + 518_400_000
        // snap1 and snap2 are above, snap0 is below
        let one_day = state.history_window("24h");
        assert_eq!(one_day.len(), 2);

        // 7d window: cutoff = latest - 604_800_000 = base
        // All three are >= cutoff (snap0 is exactly at cutoff)
        let seven_days = state.history_window("7d");
        assert_eq!(seven_days.len(), 3);
    }

    #[test]
    fn test_unknown_window_returns_all() {
        let state = LiveTelemetryState::new();
        state.push_snapshot(make_snapshot(100, &["a"]));
        state.push_snapshot(make_snapshot(200, &["b"]));

        let all = state.history_window("30d");
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_history_by_module() {
        let state = LiveTelemetryState::new();
        let base = 1_000_000_000_000u64;
        state.push_snapshot(make_snapshot(base, &["dead-code"]));
        state.push_snapshot(make_snapshot(base + 1000, &["complexity"]));
        state.push_snapshot(make_snapshot(base + 2000, &["dead-code", "security"]));

        let dc = state.history_by_module("dead-code", "7d");
        assert_eq!(dc.len(), 2);

        let sec = state.history_by_module("security", "7d");
        assert_eq!(sec.len(), 1);

        let missing = state.history_by_module("hotspot", "7d");
        assert_eq!(missing.len(), 0);
    }

    #[test]
    fn test_clear() {
        let state = LiveTelemetryState::new();
        state.push_snapshot(make_snapshot(1000, &["a"]));
        assert_eq!(state.snapshot_count(), 1);

        state.clear();
        assert_eq!(state.source(), StateSource::Empty);
        assert!(state.current().is_none());
        assert_eq!(state.snapshot_count(), 0);
    }

    #[test]
    fn test_set_source() {
        let state = LiveTelemetryState::new();
        assert_eq!(state.source(), StateSource::Empty);

        state.set_source(StateSource::Seeded);
        assert_eq!(state.source(), StateSource::Seeded);
    }

    #[test]
    fn test_thread_safety() {
        let state = LiveTelemetryState::new();
        let s1 = state.clone();
        let s2 = state.clone();

        let t1 = std::thread::spawn(move || {
            for i in 0..100 {
                s1.push_snapshot(make_snapshot(i, &["mod-a"]));
            }
        });

        let t2 = std::thread::spawn(move || {
            for i in 100..200 {
                s2.push_snapshot(make_snapshot(i, &["mod-b"]));
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(state.snapshot_count(), 200);
        assert!(state.current().is_some());
    }

    #[test]
    fn test_state_source_serde() {
        let json = serde_json::to_string(&StateSource::Live).unwrap();
        assert_eq!(json, r#""live""#);

        let parsed: StateSource = serde_json::from_str(r#""seeded""#).unwrap();
        assert_eq!(parsed, StateSource::Seeded);

        let parsed: StateSource = serde_json::from_str(r#""empty""#).unwrap();
        assert_eq!(parsed, StateSource::Empty);
    }

    #[test]
    fn test_empty_history_window() {
        let state = LiveTelemetryState::new();
        let result = state.history_window("1h");
        assert!(result.is_empty());
    }
}
