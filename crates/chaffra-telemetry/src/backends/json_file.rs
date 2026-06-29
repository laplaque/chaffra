//! JSON file backend: writes telemetry snapshot to a JSON file after each run.

use super::TelemetryBackend;
use crate::collector::ProjectedSnapshot;
use crate::error::Result;

/// Writes telemetry to a JSON file on disk.
#[derive(Debug)]
pub struct JsonFileBackend {
    path: String,
}

impl JsonFileBackend {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    /// Get the output path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl TelemetryBackend for JsonFileBackend {
    fn name(&self) -> &str {
        "json-file"
    }

    fn flush(&self, snapshot: &ProjectedSnapshot) -> Result<()> {
        let json = serde_json::to_string_pretty(snapshot)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    fn test_connection(&self) -> Result<String> {
        // Test that we can write to the target directory.
        let parent = std::path::Path::new(&self.path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        if parent.to_str() != Some("") && !parent.exists() {
            return Err(crate::error::TelemetryError::BackendError(format!(
                "directory does not exist: {}",
                parent.display()
            )));
        }
        Ok(format!("will write to {}", self.path))
    }

    fn inspect(&self, snapshot: &ProjectedSnapshot) -> Result<String> {
        Ok(serde_json::to_string_pretty(snapshot)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::TelemetryCollector;

    #[test]
    fn test_json_file_backend_flush() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("telemetry.json");
        let backend = JsonFileBackend::new(path.to_str().unwrap().to_owned());

        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(5);
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);

        backend.flush(&snapshot).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["user_summary"]["files_total"], 5);
    }

    #[test]
    fn test_json_file_backend_test_connection() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("telemetry.json");
        let backend = JsonFileBackend::new(path.to_str().unwrap().to_owned());

        let result = backend.test_connection().unwrap();
        assert!(result.contains("will write to"));
    }

    #[test]
    fn test_json_file_backend_inspect() {
        let backend = JsonFileBackend::new("test.json".to_owned());
        let collector = TelemetryCollector::with_defaults();
        let snapshot = collector
            .snapshot()
            .project_for_audience(crate::config::TelemetryAudience::On);

        let output = backend.inspect(&snapshot).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_object());
    }
}
