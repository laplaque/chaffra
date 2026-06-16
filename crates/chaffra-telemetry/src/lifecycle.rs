use crate::TelemetryCollector;
use crate::churn;
use crate::collector::TelemetrySnapshot;
use crate::config::TelemetryConfig;
use crate::live_state::LiveTelemetryState;
use crate::sampling::SamplingDecision;

pub struct FinalizeResult {
    pub snapshot: TelemetrySnapshot,
    pub findings_hash: u64,
}

pub fn finalize_and_flush(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
) -> FinalizeResult {
    finalize_inner(collector, live_state, config, false)
}

pub fn finalize_and_flush_sampled(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
) -> FinalizeResult {
    finalize_inner(collector, live_state, config, true)
}

fn finalize_inner(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
    use_sampling: bool,
) -> FinalizeResult {
    let fingerprints = collector.finding_fingerprints();
    let state_path = std::path::Path::new(churn::STATE_FILE);
    let previous_state = churn::load_state(state_path);
    let current_hash = churn::hash_fingerprints(&fingerprints);

    if let Some(ref prev) = previous_state {
        let churn_result = churn::compute_churn(&fingerprints, prev);
        collector.record_finding_churn(&churn_result);
    }

    let snapshot = collector.snapshot();
    live_state.push_snapshot(snapshot.clone());

    let should_flush = if use_sampling {
        let decision = crate::sampling::should_sample(
            config.sampling_strategy,
            config.sampling_rate,
            current_hash,
            previous_state.as_ref().map(|s| s.findings_hash),
        );
        decision == SamplingDecision::Emit
    } else {
        true
    };

    if should_flush {
        flush_to_backends(&snapshot, config);
    }

    let new_state = churn::ChurnState {
        fingerprints,
        findings_hash: current_hash,
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    };
    let _ = churn::save_state(&new_state, state_path);

    FinalizeResult {
        snapshot,
        findings_hash: current_hash,
    }
}

pub fn flush_snapshot(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
) {
    let snapshot = collector.snapshot();
    live_state.push_snapshot(snapshot.clone());
    flush_to_backends(&snapshot, config);
}

fn flush_to_backends(snapshot: &TelemetrySnapshot, config: &TelemetryConfig) {
    let (backends, _) = crate::backends::create_backends(&config.backends);
    let flushed = if config.audience.operator_enabled() {
        snapshot.clone()
    } else {
        snapshot.user_scoped()
    };
    for backend in &backends {
        if let Err(e) = backend.flush(&flushed) {
            eprintln!("Warning: telemetry backend flush failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_finalize_and_flush_pushes_snapshot() {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(5);
        collector.record_module_call("test-mod", 100, false);
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let result = finalize_and_flush(&collector, &live_state, &config);

        assert!(live_state.current().is_some());
        assert_eq!(result.snapshot.user_summary.files_total, 5);
    }

    #[test]
    fn test_finalize_returns_deterministic_hash() {
        let collector = TelemetryCollector::with_defaults();
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let r1 = finalize_and_flush(&collector, &live_state, &config);
        let r2 = finalize_and_flush(&collector, &live_state, &config);
        assert_eq!(r1.findings_hash, r2.findings_hash);
    }

    #[test]
    fn test_flush_snapshot_pushes_to_live_state() {
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(3);
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        flush_snapshot(&collector, &live_state, &config);

        let snap = live_state.current().unwrap();
        assert_eq!(snap.user_summary.files_total, 3);
    }

    #[test]
    fn test_finalize_with_fingerprints_produces_nonzero_hash() {
        let collector = TelemetryCollector::with_defaults();
        let mut fps = HashSet::new();
        fps.insert(churn::FindingFingerprint::new("rule1", "file.rs", 10));
        collector.set_finding_fingerprints(fps);

        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let result = finalize_and_flush(&collector, &live_state, &config);
        assert_ne!(result.findings_hash, 0);
    }

    #[test]
    fn test_finalize_sampled_pushes_snapshot() {
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(7);
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let result = finalize_and_flush_sampled(&collector, &live_state, &config);

        assert!(live_state.current().is_some());
        assert_eq!(result.snapshot.user_summary.files_total, 7);
    }
}
