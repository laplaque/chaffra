//! Finding churn tracking between analysis runs.
//!
//! Computes deltas (new, resolved, unchanged) by comparing current findings
//! against a persisted state file from the previous run.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Fingerprint that uniquely identifies a finding across runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FindingFingerprint {
    pub rule_id: String,
    pub file: String,
    pub start_line: u32,
}

impl FindingFingerprint {
    pub fn new(rule_id: &str, file: &str, start_line: u32) -> Self {
        Self {
            rule_id: rule_id.to_owned(),
            file: file.to_owned(),
            start_line,
        }
    }
}

/// Persisted state from the previous analysis run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChurnState {
    pub fingerprints: HashSet<FindingFingerprint>,
    pub findings_hash: u64,
    pub timestamp_ms: u64,
}

/// Result of churn computation between two runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChurnResult {
    pub new_count: u64,
    pub resolved_count: u64,
    pub unchanged_count: u64,
    pub churn_rate: f64,
}

/// Compute churn between the current set of fingerprints and the previous state.
pub fn compute_churn(current: &HashSet<FindingFingerprint>, previous: &ChurnState) -> ChurnResult {
    let new_count = current.difference(&previous.fingerprints).count() as u64;
    let resolved_count = previous.fingerprints.difference(current).count() as u64;
    let unchanged_count = current.intersection(&previous.fingerprints).count() as u64;

    let total = new_count + unchanged_count;
    let churn_rate = if total > 0 {
        new_count as f64 / total as f64
    } else {
        0.0
    };

    ChurnResult {
        new_count,
        resolved_count,
        unchanged_count,
        churn_rate,
    }
}

/// Hash a set of fingerprints for on-change sampling comparison.
pub fn hash_fingerprints(fingerprints: &HashSet<FindingFingerprint>) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut sorted: Vec<_> = fingerprints.iter().collect();
    sorted.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(a.file.cmp(&b.file))
            .then(a.start_line.cmp(&b.start_line))
    });

    let mut hasher = DefaultHasher::new();
    for fp in &sorted {
        fp.rule_id.hash(&mut hasher);
        fp.file.hash(&mut hasher);
        fp.start_line.hash(&mut hasher);
    }
    hasher.finish()
}

/// Load churn state from a file.
///
/// Returns `Ok(None)` if the file does not exist, `Ok(Some(state))` on
/// success, and `Err` on I/O or parse failures so the caller can avoid
/// overwriting valid state from a false empty baseline.
pub fn load_state(path: &Path) -> Result<Option<ChurnState>, ChurnLoadError> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let state: ChurnState =
                serde_json::from_str(&content).map_err(|e| ChurnLoadError::Parse {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            Ok(Some(state))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ChurnLoadError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

/// Errors from loading persisted churn state.
#[derive(Debug, thiserror::Error)]
pub enum ChurnLoadError {
    #[error("failed to read churn state {}: {source}", path.display())]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse churn state {}: {source}", path.display())]
    Parse {
        path: std::path::PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// Save churn state to a file atomically via temp-file-then-rename.
pub fn save_state(state: &ChurnState, path: &Path) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(std::io::Error::other)?;
    use std::io::Write;
    tmp.write_all(json.as_bytes())?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

static CHURN_LOCKS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<std::path::PathBuf, Arc<Mutex<()>>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

/// Get or create a per-project churn lock.
pub fn project_lock(project_root: &Path) -> Arc<Mutex<()>> {
    let mut locks = CHURN_LOCKS.lock().unwrap();
    locks
        .entry(project_root.to_path_buf())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Default state file path.
pub const STATE_FILE: &str = ".chaffra-telemetry-state.json";

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(rule: &str, file: &str, line: u32) -> FindingFingerprint {
        FindingFingerprint::new(rule, file, line)
    }

    #[test]
    fn test_churn_no_previous() {
        let current: HashSet<_> = [fp("dc:unused", "a.go", 10), fp("dc:unused", "b.go", 20)]
            .into_iter()
            .collect();
        let previous = ChurnState::default();
        let result = compute_churn(&current, &previous);
        assert_eq!(result.new_count, 2);
        assert_eq!(result.resolved_count, 0);
        assert_eq!(result.unchanged_count, 0);
        assert!((result.churn_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_churn_identical_runs() {
        let findings: HashSet<_> = [fp("dc:unused", "a.go", 10)].into_iter().collect();
        let previous = ChurnState {
            fingerprints: findings.clone(),
            findings_hash: 0,
            timestamp_ms: 0,
        };
        let result = compute_churn(&findings, &previous);
        assert_eq!(result.new_count, 0);
        assert_eq!(result.resolved_count, 0);
        assert_eq!(result.unchanged_count, 1);
        assert!((result.churn_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_churn_mixed() {
        let current: HashSet<_> = [fp("dc:unused", "a.go", 10), fp("cx:high", "c.go", 30)]
            .into_iter()
            .collect();
        let previous = ChurnState {
            fingerprints: [fp("dc:unused", "a.go", 10), fp("dc:unused", "b.go", 20)]
                .into_iter()
                .collect(),
            findings_hash: 0,
            timestamp_ms: 0,
        };
        let result = compute_churn(&current, &previous);
        assert_eq!(result.new_count, 1);
        assert_eq!(result.resolved_count, 1);
        assert_eq!(result.unchanged_count, 1);
        assert!((result.churn_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_churn_all_resolved() {
        let current: HashSet<_> = HashSet::new();
        let previous = ChurnState {
            fingerprints: [fp("dc:unused", "a.go", 10)].into_iter().collect(),
            findings_hash: 0,
            timestamp_ms: 0,
        };
        let result = compute_churn(&current, &previous);
        assert_eq!(result.new_count, 0);
        assert_eq!(result.resolved_count, 1);
        assert_eq!(result.unchanged_count, 0);
        assert!((result.churn_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hash_fingerprints_deterministic() {
        let set1: HashSet<_> = [fp("a", "f1", 1), fp("b", "f2", 2)].into_iter().collect();
        let set2: HashSet<_> = [fp("b", "f2", 2), fp("a", "f1", 1)].into_iter().collect();
        assert_eq!(hash_fingerprints(&set1), hash_fingerprints(&set2));
    }

    #[test]
    fn test_hash_fingerprints_different() {
        let set1: HashSet<_> = [fp("a", "f1", 1)].into_iter().collect();
        let set2: HashSet<_> = [fp("b", "f2", 2)].into_iter().collect();
        assert_ne!(hash_fingerprints(&set1), hash_fingerprints(&set2));
    }

    #[test]
    fn test_state_roundtrip() {
        let dir = std::env::temp_dir().join("churn_test_roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(STATE_FILE);

        let state = ChurnState {
            fingerprints: [fp("dc:unused", "a.go", 10)].into_iter().collect(),
            findings_hash: 12345,
            timestamp_ms: 1000,
        };

        save_state(&state, &path).unwrap();
        let loaded = load_state(&path).unwrap().unwrap();
        assert_eq!(loaded.fingerprints, state.fingerprints);
        assert_eq!(loaded.findings_hash, 12345);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_state_missing_file() {
        let result = load_state(Path::new("/nonexistent/path/state.json")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_state_corrupted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, "not valid json{{{").unwrap();
        let result = load_state(&path);
        assert!(result.is_err());
    }
}
