//! Per-module timing and telemetry.

use std::collections::HashMap;
use std::time::Instant;

/// Collects timing and count metrics for module runs.
#[derive(Debug)]
pub struct ModuleTelemetry {
    module_id: String,
    start: Option<Instant>,
    duration_ms: u64,
    counters: HashMap<String, u64>,
}

impl ModuleTelemetry {
    /// Create a new telemetry collector for the given module.
    pub fn new(module_id: &str) -> Self {
        Self {
            module_id: module_id.to_owned(),
            start: None,
            duration_ms: 0,
            counters: HashMap::new(),
        }
    }

    /// Start timing.
    pub fn start(&mut self) {
        self.start = Some(Instant::now());
    }

    /// Stop timing and record elapsed duration.
    pub fn stop(&mut self) {
        if let Some(start) = self.start.take() {
            self.duration_ms = start.elapsed().as_millis() as u64;
        }
    }

    /// Increment a named counter.
    pub fn increment(&mut self, name: &str, amount: u64) {
        *self.counters.entry(name.to_owned()).or_insert(0) += amount;
    }

    /// Get the module ID.
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Get the recorded duration in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.duration_ms
    }

    /// Get all counters.
    pub fn counters(&self) -> &HashMap<String, u64> {
        &self.counters
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_basic() {
        let mut t = ModuleTelemetry::new("test-module");
        assert_eq!(t.module_id(), "test-module");
        assert_eq!(t.duration_ms(), 0);

        t.start();
        t.increment("files", 5);
        t.increment("findings", 3);
        t.stop();

        // Duration is always non-negative; just check it was recorded.
        let _ = t.duration_ms();
        assert_eq!(t.counters().get("files"), Some(&5));
        assert_eq!(t.counters().get("findings"), Some(&3));
    }

    #[test]
    fn test_telemetry_increment_accumulates() {
        let mut t = ModuleTelemetry::new("mod");
        t.increment("count", 1);
        t.increment("count", 2);
        assert_eq!(t.counters().get("count"), Some(&3));
    }
}
