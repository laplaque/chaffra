//! Sampling strategies for operator telemetry in high-volume environments.

use serde::{Deserialize, Serialize};

/// How to decide whether operator metrics should be emitted for a given run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SamplingStrategy {
    /// Emit based on a random rate (1.0 = every run, 0.1 = 10%).
    #[default]
    Rate,
    /// Emit only when findings change compared to the previous run.
    OnChange,
}

impl SamplingStrategy {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "rate" => Some(Self::Rate),
            "on-change" | "onchange" | "change" => Some(Self::OnChange),
            _ => None,
        }
    }
}

/// Whether a given run should emit operator telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingDecision {
    Emit,
    Skip,
}

/// Decide whether to emit operator telemetry for this run.
pub fn should_sample(
    strategy: SamplingStrategy,
    rate: f64,
    current_findings_hash: u64,
    previous_findings_hash: Option<u64>,
) -> SamplingDecision {
    match strategy {
        SamplingStrategy::Rate => {
            if rate >= 1.0 {
                return SamplingDecision::Emit;
            }
            if rate <= 0.0 {
                return SamplingDecision::Skip;
            }
            let sample: f64 = simple_random();
            if sample < rate {
                SamplingDecision::Emit
            } else {
                SamplingDecision::Skip
            }
        }
        SamplingStrategy::OnChange => match previous_findings_hash {
            Some(prev) if prev == current_findings_hash => SamplingDecision::Skip,
            _ => SamplingDecision::Emit,
        },
    }
}

fn simple_random() -> f64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::SystemTime;

    let mut hasher = DefaultHasher::new();
    SystemTime::now().hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let hash = hasher.finish();
    (hash % 10000) as f64 / 10000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_always_emit() {
        let decision = should_sample(SamplingStrategy::Rate, 1.0, 0, None);
        assert_eq!(decision, SamplingDecision::Emit);
    }

    #[test]
    fn test_rate_never_emit() {
        let decision = should_sample(SamplingStrategy::Rate, 0.0, 0, None);
        assert_eq!(decision, SamplingDecision::Skip);
    }

    #[test]
    fn test_on_change_no_previous() {
        let decision = should_sample(SamplingStrategy::OnChange, 1.0, 12345, None);
        assert_eq!(decision, SamplingDecision::Emit);
    }

    #[test]
    fn test_on_change_same_hash() {
        let decision = should_sample(SamplingStrategy::OnChange, 1.0, 12345, Some(12345));
        assert_eq!(decision, SamplingDecision::Skip);
    }

    #[test]
    fn test_on_change_different_hash() {
        let decision = should_sample(SamplingStrategy::OnChange, 1.0, 12345, Some(99999));
        assert_eq!(decision, SamplingDecision::Emit);
    }

    #[test]
    fn test_strategy_from_str() {
        assert_eq!(
            SamplingStrategy::from_str_loose("rate"),
            Some(SamplingStrategy::Rate)
        );
        assert_eq!(
            SamplingStrategy::from_str_loose("on-change"),
            Some(SamplingStrategy::OnChange)
        );
        assert_eq!(
            SamplingStrategy::from_str_loose("onchange"),
            Some(SamplingStrategy::OnChange)
        );
        assert_eq!(SamplingStrategy::from_str_loose("bogus"), None);
    }

    #[test]
    fn test_rate_partial_sampling() {
        let mut emit_count = 0;
        for _ in 0..100 {
            if should_sample(SamplingStrategy::Rate, 0.5, 0, None) == SamplingDecision::Emit {
                emit_count += 1;
            }
        }
        assert!(emit_count > 0, "should emit at least some");
        assert!(emit_count < 100, "should skip at least some");
    }
}
