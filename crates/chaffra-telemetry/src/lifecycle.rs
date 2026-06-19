use crate::TelemetryCollector;
use crate::churn;
use crate::collector::TelemetrySnapshot;
use crate::config::TelemetryConfig;
use crate::live_state::LiveTelemetryState;
use crate::sampling::SamplingDecision;
use std::path::Path;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct FinalizeResult {
    pub snapshot: TelemetrySnapshot,
    pub findings_hash: u64,
}

pub fn finalize_and_flush(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
    project_root: &Path,
) -> FinalizeResult {
    finalize_inner(collector, live_state, config, false, project_root)
}

pub fn finalize_and_flush_sampled(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
    project_root: &Path,
) -> FinalizeResult {
    finalize_inner(collector, live_state, config, true, project_root)
}

fn finalize_inner(
    collector: &TelemetryCollector,
    live_state: &LiveTelemetryState,
    config: &TelemetryConfig,
    use_sampling: bool,
    project_root: &Path,
) -> FinalizeResult {
    let fingerprints = collector.finding_fingerprints();
    let state_path = project_root.join(churn::STATE_FILE);

    let canonical_root = project_root
        .canonicalize()
        .unwrap_or(project_root.to_path_buf());
    let lock = churn::project_lock(&canonical_root);
    let current_hash = churn::hash_fingerprints(&fingerprints);

    let guard = lock.lock().unwrap_or_else(|e| e.into_inner());

    let previous_state = match churn::load_state(&state_path) {
        Ok(prev) => prev,
        Err(e) => {
            eprintln!("Warning: {e}; skipping churn and preserving existing state");
            let snapshot = collector.snapshot();
            live_state.push_snapshot(snapshot.clone());
            let should_flush = !use_sampling || should_flush_sampled(config, current_hash, None);
            drop(guard);
            if should_flush {
                flush_to_backends(&snapshot, config);
            }
            return FinalizeResult {
                snapshot,
                findings_hash: current_hash,
            };
        }
    };

    if let Some(ref prev) = previous_state {
        let churn_result = churn::compute_churn(&fingerprints, prev);
        collector.record_finding_churn(&churn_result);
    }

    let snapshot = collector.snapshot();
    live_state.push_snapshot(snapshot.clone());

    let should_flush = !use_sampling
        || should_flush_sampled(
            config,
            current_hash,
            previous_state.as_ref().map(|s| s.findings_hash),
        );

    let new_state = churn::ChurnState {
        fingerprints,
        findings_hash: current_hash,
        timestamp_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
    };
    if let Err(e) = churn::save_state(&new_state, &state_path) {
        eprintln!(
            "Warning: failed to persist telemetry churn state to {}: {e}",
            state_path.display()
        );
    }

    drop(guard);

    if should_flush {
        flush_to_backends(&snapshot, config);
    }

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

fn should_flush_sampled(
    config: &TelemetryConfig,
    current_hash: u64,
    previous_hash: Option<u64>,
) -> bool {
    let decision = crate::sampling::should_sample(
        config.sampling_strategy,
        config.sampling_rate,
        current_hash,
        previous_hash,
    );
    decision == SamplingDecision::Emit
}

fn flush_to_backends(snapshot: &TelemetrySnapshot, config: &TelemetryConfig) {
    if matches!(config.audience, crate::config::TelemetryAudience::Off) {
        return;
    }
    let (backends, _) = crate::backends::create_backends(&config.backends);
    let flushed = snapshot.project_for_audience(config.audience);
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
        let tmp = tempfile::tempdir().unwrap();
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(5);
        collector.record_module_call("test-mod", 100, false);
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let result = finalize_and_flush(&collector, &live_state, &config, tmp.path());

        assert!(live_state.current().is_some());
        assert_eq!(result.snapshot.user_summary.files_total, 5);
    }

    #[test]
    fn test_finalize_returns_deterministic_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let collector = TelemetryCollector::with_defaults();
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let r1 = finalize_and_flush(&collector, &live_state, &config, tmp.path());
        let r2 = finalize_and_flush(&collector, &live_state, &config, tmp.path());
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
        let tmp = tempfile::tempdir().unwrap();
        let collector = TelemetryCollector::with_defaults();
        let mut fps = HashSet::new();
        fps.insert(churn::FindingFingerprint::new("rule1", "file.rs", 10));
        collector.set_finding_fingerprints(fps);

        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let result = finalize_and_flush(&collector, &live_state, &config, tmp.path());
        assert_ne!(result.findings_hash, 0);
    }

    #[test]
    fn test_finalize_sampled_pushes_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(7);
        let live_state = LiveTelemetryState::new();
        let config = TelemetryConfig::default();

        let result = finalize_and_flush_sampled(&collector, &live_state, &config, tmp.path());

        assert!(live_state.current().is_some());
        assert_eq!(result.snapshot.user_summary.files_total, 7);
    }
}
