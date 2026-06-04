//! Impact tracking: snapshots, trend analysis, and catch rate metrics.
//!
//! Provides the ability to save analysis snapshots, compare them over time,
//! and compute trend directions and catch rates (findings fixed vs introduced).

use chaffra_core::diagnostic::{AnalysisResult, Finding, ProjectHealth};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A point-in-time snapshot of analysis results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// ISO 8601 timestamp of when the snapshot was taken.
    pub timestamp: String,
    /// Optional label (e.g. git ref, version tag).
    pub label: Option<String>,
    /// Total findings count by rule ID.
    pub finding_counts: HashMap<String, u64>,
    /// Health score at snapshot time (0-100).
    pub health_score: Option<u32>,
    /// Total files analyzed.
    pub files_analyzed: u64,
    /// Aggregate metrics (e.g. total complexity, dead code count).
    pub metrics: HashMap<String, f64>,
}

/// Direction of a metric trend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrendDirection {
    /// Metric improved (fewer findings or higher health).
    Improving,
    /// Metric stayed the same.
    Stable,
    /// Metric worsened (more findings or lower health).
    Regressing,
}

impl std::fmt::Display for TrendDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrendDirection::Improving => write!(f, "improving"),
            TrendDirection::Stable => write!(f, "stable"),
            TrendDirection::Regressing => write!(f, "regressing"),
        }
    }
}

/// Trend for a single metric between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricTrend {
    /// Metric name.
    pub name: String,
    /// Value in the baseline snapshot.
    pub baseline: f64,
    /// Value in the current snapshot.
    pub current: f64,
    /// Absolute change (current - baseline).
    pub delta: f64,
    /// Trend direction.
    pub direction: TrendDirection,
}

/// Catch rate: how many findings were fixed vs introduced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchRate {
    /// Findings present in baseline but not in current (fixed).
    pub fixed: u64,
    /// Findings present in current but not in baseline (introduced).
    pub introduced: u64,
    /// Findings present in both (persisted).
    pub persisted: u64,
    /// Fix rate: fixed / (fixed + persisted), as a percentage.
    pub fix_rate_pct: f64,
}

/// Full trend report comparing two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendReport {
    /// Baseline snapshot label/timestamp.
    pub baseline_label: String,
    /// Current snapshot label/timestamp.
    pub current_label: String,
    /// Per-metric trends.
    pub trends: Vec<MetricTrend>,
    /// Catch rate analysis.
    pub catch_rate: CatchRate,
}

/// Create a snapshot from an analysis result and optional health data.
pub fn create_snapshot(
    result: &AnalysisResult,
    health: Option<&ProjectHealth>,
    label: Option<String>,
) -> Snapshot {
    let mut finding_counts: HashMap<String, u64> = HashMap::new();
    for finding in &result.findings {
        *finding_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut metrics: HashMap<String, f64> = HashMap::new();
    metrics.insert("total_findings".to_owned(), result.findings.len() as f64);
    metrics.insert(
        "files_analyzed".to_owned(),
        result.metrics.files_analyzed as f64,
    );

    for (k, v) in &result.metrics.counters {
        metrics.insert(k.clone(), *v as f64);
    }

    let now = current_timestamp();

    Snapshot {
        timestamp: now,
        label,
        finding_counts,
        health_score: health.map(|h| h.score),
        files_analyzed: result.metrics.files_analyzed,
        metrics,
    }
}

/// Save a snapshot to a JSON file.
pub fn save_snapshot(snapshot: &Snapshot, path: &Path) -> Result<(), SnapshotError> {
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| SnapshotError::Serialize(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| SnapshotError::Io(e.to_string()))?;
    Ok(())
}

/// Load a snapshot from a JSON file.
pub fn load_snapshot(path: &Path) -> Result<Snapshot, SnapshotError> {
    let content = std::fs::read_to_string(path).map_err(|e| SnapshotError::Io(e.to_string()))?;
    serde_json::from_str(&content).map_err(|e| SnapshotError::Deserialize(e.to_string()))
}

/// Compare two snapshots and produce a trend report.
pub fn compare_snapshots(baseline: &Snapshot, current: &Snapshot) -> TrendReport {
    let mut trends = Vec::new();

    // Collect all metric keys from both snapshots
    let mut all_keys: Vec<String> = baseline.metrics.keys().cloned().collect();
    for key in current.metrics.keys() {
        if !all_keys.contains(key) {
            all_keys.push(key.clone());
        }
    }
    all_keys.sort();

    for key in &all_keys {
        let base_val = baseline.metrics.get(key).copied().unwrap_or(0.0);
        let curr_val = current.metrics.get(key).copied().unwrap_or(0.0);
        let delta = curr_val - base_val;

        let direction = if key == "health_score" {
            // Higher health is better
            trend_direction_higher_is_better(base_val, curr_val)
        } else {
            // For findings/complexity, lower is better
            trend_direction_lower_is_better(base_val, curr_val)
        };

        trends.push(MetricTrend {
            name: key.clone(),
            baseline: base_val,
            current: curr_val,
            delta,
            direction,
        });
    }

    // Add health score trend if available
    if let (Some(base_health), Some(curr_health)) = (baseline.health_score, current.health_score) {
        let delta = f64::from(curr_health) - f64::from(base_health);
        trends.push(MetricTrend {
            name: "health_score".to_owned(),
            baseline: f64::from(base_health),
            current: f64::from(curr_health),
            delta,
            direction: trend_direction_higher_is_better(
                f64::from(base_health),
                f64::from(curr_health),
            ),
        });
    }

    let catch_rate = compute_catch_rate(baseline, current);

    TrendReport {
        baseline_label: baseline
            .label
            .clone()
            .unwrap_or_else(|| baseline.timestamp.clone()),
        current_label: current
            .label
            .clone()
            .unwrap_or_else(|| current.timestamp.clone()),
        trends,
        catch_rate,
    }
}

/// Compute catch rate between two snapshots based on finding counts by rule.
fn compute_catch_rate(baseline: &Snapshot, current: &Snapshot) -> CatchRate {
    let mut fixed: u64 = 0;
    let mut introduced: u64 = 0;
    let mut persisted: u64 = 0;

    // Collect all rule IDs
    let mut all_rules: Vec<String> = baseline.finding_counts.keys().cloned().collect();
    for rule in current.finding_counts.keys() {
        if !all_rules.contains(rule) {
            all_rules.push(rule.clone());
        }
    }

    for rule in &all_rules {
        let base_count = baseline.finding_counts.get(rule).copied().unwrap_or(0);
        let curr_count = current.finding_counts.get(rule).copied().unwrap_or(0);

        if curr_count < base_count {
            fixed += base_count - curr_count;
            persisted += curr_count;
        } else if curr_count > base_count {
            introduced += curr_count - base_count;
            persisted += base_count;
        } else {
            persisted += curr_count;
        }
    }

    let total_addressable = fixed + persisted;
    let fix_rate_pct = if total_addressable > 0 {
        (fixed as f64 / total_addressable as f64) * 100.0
    } else {
        0.0
    };

    CatchRate {
        fixed,
        introduced,
        persisted,
        fix_rate_pct,
    }
}

/// Format a trend report as a markdown table.
pub fn format_trend_table(report: &TrendReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "## Impact Report: {} -> {}\n\n",
        report.baseline_label, report.current_label
    ));

    out.push_str("| Metric | Baseline | Current | Delta | Trend |\n");
    out.push_str("|--------|----------|---------|-------|-------|\n");

    for trend in &report.trends {
        let arrow = match trend.direction {
            TrendDirection::Improving => "v (improving)",
            TrendDirection::Stable => "= (stable)",
            TrendDirection::Regressing => "^ (regressing)",
        };
        out.push_str(&format!(
            "| {} | {:.1} | {:.1} | {:+.1} | {} |\n",
            trend.name, trend.baseline, trend.current, trend.delta, arrow,
        ));
    }

    out.push('\n');
    out.push_str("### Catch Rate\n\n");
    out.push_str(&format!("- Fixed: {}\n", report.catch_rate.fixed));
    out.push_str(&format!("- Introduced: {}\n", report.catch_rate.introduced));
    out.push_str(&format!("- Persisted: {}\n", report.catch_rate.persisted));
    out.push_str(&format!(
        "- Fix rate: {:.1}%\n",
        report.catch_rate.fix_rate_pct
    ));

    out
}

/// Format a trend report as JSON.
pub fn format_trend_json(report: &TrendReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_owned())
}

fn trend_direction_lower_is_better(baseline: f64, current: f64) -> TrendDirection {
    let epsilon = 0.001;
    if (current - baseline).abs() < epsilon {
        TrendDirection::Stable
    } else if current < baseline {
        TrendDirection::Improving
    } else {
        TrendDirection::Regressing
    }
}

fn trend_direction_higher_is_better(baseline: f64, current: f64) -> TrendDirection {
    let epsilon = 0.001;
    if (current - baseline).abs() < epsilon {
        TrendDirection::Stable
    } else if current > baseline {
        TrendDirection::Improving
    } else {
        TrendDirection::Regressing
    }
}

fn current_timestamp() -> String {
    // Simple UTC timestamp without external chrono dependency
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{secs}")
}

/// Errors from snapshot operations.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("deserialization error: {0}")]
    Deserialize(String),
}

/// Build a snapshot from raw findings list and health data (convenience for CLI).
pub fn snapshot_from_findings(
    findings: &[Finding],
    files_analyzed: u64,
    health: Option<&ProjectHealth>,
    label: Option<String>,
) -> Snapshot {
    let mut finding_counts: HashMap<String, u64> = HashMap::new();
    for finding in findings {
        *finding_counts.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut metrics: HashMap<String, f64> = HashMap::new();
    metrics.insert("total_findings".to_owned(), findings.len() as f64);
    metrics.insert("files_analyzed".to_owned(), files_analyzed as f64);

    Snapshot {
        timestamp: current_timestamp(),
        label,
        finding_counts,
        health_score: health.map(|h| h.score),
        files_analyzed,
        metrics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::{HealthGrade, Location, ModuleMetrics};

    fn make_finding(rule_id: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_owned(),
            message: format!("test finding for {rule_id}"),
            severity: chaffra_core::diagnostic::Severity::Warning,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 1,
                end_line: 1,
                start_column: 0,
                end_column: 10,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }
    }

    fn make_result(findings: Vec<Finding>) -> AnalysisResult {
        let count = findings.len() as u64;
        AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: 10,
                duration_ms: 100,
                counters: HashMap::new(),
            },
        }
    }

    fn make_health(score: u32) -> ProjectHealth {
        ProjectHealth {
            score,
            grade: HealthGrade::from_score(score),
            files: vec![],
            total_files: 10,
        }
    }

    // --- Snapshot creation tests ---

    #[test]
    fn test_create_snapshot_basic() {
        let result = make_result(vec![
            make_finding("unused-function"),
            make_finding("unused-function"),
            make_finding("high-cyclomatic"),
        ]);
        let health = make_health(85);

        let snapshot = create_snapshot(&result, Some(&health), Some("v1.0".to_owned()));
        assert_eq!(snapshot.label, Some("v1.0".to_owned()));
        assert_eq!(snapshot.health_score, Some(85));
        assert_eq!(snapshot.files_analyzed, 10);
        assert_eq!(snapshot.finding_counts.get("unused-function"), Some(&2));
        assert_eq!(snapshot.finding_counts.get("high-cyclomatic"), Some(&1));
        assert_eq!(snapshot.metrics.get("total_findings"), Some(&3.0));
    }

    #[test]
    fn test_create_snapshot_no_health() {
        let result = make_result(vec![]);
        let snapshot = create_snapshot(&result, None, None);
        assert!(snapshot.health_score.is_none());
        assert!(snapshot.label.is_none());
    }

    // --- Snapshot save/load tests ---

    #[test]
    fn test_snapshot_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snapshot.json");

        let result = make_result(vec![make_finding("unused-import")]);
        let snapshot = create_snapshot(&result, Some(&make_health(90)), Some("test".to_owned()));

        save_snapshot(&snapshot, &path).unwrap();
        let loaded = load_snapshot(&path).unwrap();

        assert_eq!(loaded.label, snapshot.label);
        assert_eq!(loaded.health_score, snapshot.health_score);
        assert_eq!(loaded.finding_counts, snapshot.finding_counts);
    }

    #[test]
    fn test_load_snapshot_missing_file() {
        let result = load_snapshot(Path::new("/nonexistent/snapshot.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_snapshot_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json").unwrap();
        let result = load_snapshot(&path);
        assert!(result.is_err());
    }

    // --- Trend comparison tests ---

    #[test]
    fn test_compare_snapshots_improving() {
        let baseline = Snapshot {
            timestamp: "1000".to_owned(),
            label: Some("baseline".to_owned()),
            finding_counts: {
                let mut m = HashMap::new();
                m.insert("unused-function".to_owned(), 10);
                m
            },
            health_score: Some(70),
            files_analyzed: 20,
            metrics: {
                let mut m = HashMap::new();
                m.insert("total_findings".to_owned(), 10.0);
                m
            },
        };

        let current = Snapshot {
            timestamp: "2000".to_owned(),
            label: Some("current".to_owned()),
            finding_counts: {
                let mut m = HashMap::new();
                m.insert("unused-function".to_owned(), 5);
                m
            },
            health_score: Some(85),
            files_analyzed: 20,
            metrics: {
                let mut m = HashMap::new();
                m.insert("total_findings".to_owned(), 5.0);
                m
            },
        };

        let report = compare_snapshots(&baseline, &current);
        assert_eq!(report.baseline_label, "baseline");
        assert_eq!(report.current_label, "current");

        // total_findings went from 10 to 5: improving
        let findings_trend = report
            .trends
            .iter()
            .find(|t| t.name == "total_findings")
            .unwrap();
        assert_eq!(findings_trend.direction, TrendDirection::Improving);
        assert_eq!(findings_trend.delta, -5.0);

        // health score went from 70 to 85: improving
        let health_trend = report
            .trends
            .iter()
            .find(|t| t.name == "health_score")
            .unwrap();
        assert_eq!(health_trend.direction, TrendDirection::Improving);
    }

    #[test]
    fn test_compare_snapshots_regressing() {
        let baseline = Snapshot {
            timestamp: "1000".to_owned(),
            label: None,
            finding_counts: HashMap::new(),
            health_score: Some(90),
            files_analyzed: 10,
            metrics: {
                let mut m = HashMap::new();
                m.insert("total_findings".to_owned(), 2.0);
                m
            },
        };

        let current = Snapshot {
            timestamp: "2000".to_owned(),
            label: None,
            finding_counts: HashMap::new(),
            health_score: Some(75),
            files_analyzed: 10,
            metrics: {
                let mut m = HashMap::new();
                m.insert("total_findings".to_owned(), 8.0);
                m
            },
        };

        let report = compare_snapshots(&baseline, &current);

        let findings_trend = report
            .trends
            .iter()
            .find(|t| t.name == "total_findings")
            .unwrap();
        assert_eq!(findings_trend.direction, TrendDirection::Regressing);

        let health_trend = report
            .trends
            .iter()
            .find(|t| t.name == "health_score")
            .unwrap();
        assert_eq!(health_trend.direction, TrendDirection::Regressing);
    }

    #[test]
    fn test_compare_snapshots_stable() {
        let snapshot = Snapshot {
            timestamp: "1000".to_owned(),
            label: Some("same".to_owned()),
            finding_counts: {
                let mut m = HashMap::new();
                m.insert("rule-a".to_owned(), 5);
                m
            },
            health_score: Some(80),
            files_analyzed: 10,
            metrics: {
                let mut m = HashMap::new();
                m.insert("total_findings".to_owned(), 5.0);
                m
            },
        };

        let report = compare_snapshots(&snapshot, &snapshot);
        for trend in &report.trends {
            assert_eq!(trend.direction, TrendDirection::Stable);
            assert!((trend.delta).abs() < 0.01);
        }
    }

    // --- Catch rate tests ---

    #[test]
    fn test_catch_rate_fixed_and_introduced() {
        let baseline = Snapshot {
            timestamp: "1000".to_owned(),
            label: None,
            finding_counts: {
                let mut m = HashMap::new();
                m.insert("rule-a".to_owned(), 10);
                m.insert("rule-b".to_owned(), 5);
                m
            },
            health_score: None,
            files_analyzed: 10,
            metrics: HashMap::new(),
        };

        let current = Snapshot {
            timestamp: "2000".to_owned(),
            label: None,
            finding_counts: {
                let mut m = HashMap::new();
                m.insert("rule-a".to_owned(), 7); // 3 fixed
                m.insert("rule-b".to_owned(), 5); // same
                m.insert("rule-c".to_owned(), 2); // 2 introduced
                m
            },
            health_score: None,
            files_analyzed: 10,
            metrics: HashMap::new(),
        };

        let rate = compute_catch_rate(&baseline, &current);
        assert_eq!(rate.fixed, 3);
        assert_eq!(rate.introduced, 2);
        assert_eq!(rate.persisted, 12); // 7 from rule-a + 5 from rule-b
        // fix_rate = 3 / (3 + 12) = 20%
        assert!((rate.fix_rate_pct - 20.0).abs() < 0.1);
    }

    #[test]
    fn test_catch_rate_all_fixed() {
        let baseline = Snapshot {
            timestamp: "1000".to_owned(),
            label: None,
            finding_counts: {
                let mut m = HashMap::new();
                m.insert("rule-a".to_owned(), 5);
                m
            },
            health_score: None,
            files_analyzed: 10,
            metrics: HashMap::new(),
        };

        let current = Snapshot {
            timestamp: "2000".to_owned(),
            label: None,
            finding_counts: HashMap::new(),
            health_score: None,
            files_analyzed: 10,
            metrics: HashMap::new(),
        };

        let rate = compute_catch_rate(&baseline, &current);
        assert_eq!(rate.fixed, 5);
        assert_eq!(rate.introduced, 0);
        assert_eq!(rate.persisted, 0);
        assert!((rate.fix_rate_pct - 100.0).abs() < 0.1);
    }

    #[test]
    fn test_catch_rate_empty() {
        let empty = Snapshot {
            timestamp: "1000".to_owned(),
            label: None,
            finding_counts: HashMap::new(),
            health_score: None,
            files_analyzed: 0,
            metrics: HashMap::new(),
        };

        let rate = compute_catch_rate(&empty, &empty);
        assert_eq!(rate.fixed, 0);
        assert_eq!(rate.introduced, 0);
        assert_eq!(rate.persisted, 0);
        assert_eq!(rate.fix_rate_pct, 0.0);
    }

    // --- Formatting tests ---

    #[test]
    fn test_format_trend_table() {
        let report = TrendReport {
            baseline_label: "v1.0".to_owned(),
            current_label: "v1.1".to_owned(),
            trends: vec![MetricTrend {
                name: "total_findings".to_owned(),
                baseline: 10.0,
                current: 5.0,
                delta: -5.0,
                direction: TrendDirection::Improving,
            }],
            catch_rate: CatchRate {
                fixed: 5,
                introduced: 0,
                persisted: 5,
                fix_rate_pct: 50.0,
            },
        };

        let table = format_trend_table(&report);
        assert!(table.contains("v1.0"));
        assert!(table.contains("v1.1"));
        assert!(table.contains("total_findings"));
        assert!(table.contains("improving"));
        assert!(table.contains("Fixed: 5"));
        assert!(table.contains("50.0%"));
    }

    #[test]
    fn test_format_trend_json() {
        let report = TrendReport {
            baseline_label: "a".to_owned(),
            current_label: "b".to_owned(),
            trends: vec![],
            catch_rate: CatchRate {
                fixed: 0,
                introduced: 0,
                persisted: 0,
                fix_rate_pct: 0.0,
            },
        };

        let json = format_trend_json(&report);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["baseline_label"], "a");
        assert_eq!(parsed["current_label"], "b");
    }

    // --- TrendDirection display ---

    #[test]
    fn test_trend_direction_display() {
        let cases = vec![
            (TrendDirection::Improving, "improving"),
            (TrendDirection::Stable, "stable"),
            (TrendDirection::Regressing, "regressing"),
        ];
        for (dir, expected) in cases {
            assert_eq!(dir.to_string(), expected);
        }
    }

    // --- Helper function tests ---

    #[test]
    fn test_trend_direction_lower_is_better() {
        assert_eq!(
            trend_direction_lower_is_better(10.0, 5.0),
            TrendDirection::Improving
        );
        assert_eq!(
            trend_direction_lower_is_better(5.0, 10.0),
            TrendDirection::Regressing
        );
        assert_eq!(
            trend_direction_lower_is_better(5.0, 5.0),
            TrendDirection::Stable
        );
    }

    #[test]
    fn test_trend_direction_higher_is_better() {
        assert_eq!(
            trend_direction_higher_is_better(70.0, 85.0),
            TrendDirection::Improving
        );
        assert_eq!(
            trend_direction_higher_is_better(85.0, 70.0),
            TrendDirection::Regressing
        );
        assert_eq!(
            trend_direction_higher_is_better(80.0, 80.0),
            TrendDirection::Stable
        );
    }

    // --- snapshot_from_findings tests ---

    #[test]
    fn test_snapshot_from_findings() {
        let findings = vec![
            make_finding("rule-a"),
            make_finding("rule-a"),
            make_finding("rule-b"),
        ];
        let health = make_health(80);

        let snapshot =
            snapshot_from_findings(&findings, 15, Some(&health), Some("test".to_owned()));
        assert_eq!(snapshot.finding_counts.get("rule-a"), Some(&2));
        assert_eq!(snapshot.finding_counts.get("rule-b"), Some(&1));
        assert_eq!(snapshot.health_score, Some(80));
        assert_eq!(snapshot.files_analyzed, 15);
    }

    // --- SnapshotError display ---

    #[test]
    fn test_snapshot_error_display() {
        let err = SnapshotError::Io("disk full".to_owned());
        assert_eq!(err.to_string(), "I/O error: disk full");

        let err = SnapshotError::Serialize("bad data".to_owned());
        assert_eq!(err.to_string(), "serialization error: bad data");

        let err = SnapshotError::Deserialize("parse fail".to_owned());
        assert_eq!(err.to_string(), "deserialization error: parse fail");
    }
}
