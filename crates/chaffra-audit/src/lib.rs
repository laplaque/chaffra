//! PR risk assessment and audit gating.
//!
//! Compares current analysis results against a stored baseline to determine
//! whether a pull request introduces new issues. Supports `new-only` and `all`
//! gating modes with configurable tolerance thresholds. Emits a structured
//! verdict (pass / warn / fail) consumed by CI and the CLI `audit` subcommand.

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, Location, ModuleInfo, ModuleMetrics, Rule,
    RuleExplanation, Severity,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Audit verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Pass => write!(f, "pass"),
            Verdict::Warn => write!(f, "warn"),
            Verdict::Fail => write!(f, "fail"),
        }
    }
}

/// Gate mode controlling which findings are counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateMode {
    /// Only new findings (not present in baseline) are considered.
    NewOnly,
    /// All findings (regardless of baseline) are considered.
    All,
}

impl GateMode {
    /// Parse gate mode from a string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "new-only" | "newonly" | "new" => Some(GateMode::NewOnly),
            "all" => Some(GateMode::All),
            _ => None,
        }
    }
}

/// A stored baseline of findings for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    /// ISO-8601 timestamp when baseline was captured.
    pub timestamp: String,
    /// Findings in the baseline snapshot.
    pub findings: Vec<BaselineFinding>,
}

/// A single finding in a baseline, keyed by rule + file + line for identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineFinding {
    pub rule_id: String,
    pub file: String,
    pub start_line: u32,
    pub message: String,
}

impl BaselineFinding {
    /// Create from a full finding.
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            rule_id: finding.rule_id.clone(),
            file: finding.location.file.clone(),
            start_line: finding.location.start_line,
            message: finding.message.clone(),
        }
    }
}

/// Result of an audit comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub verdict: Verdict,
    pub gate_mode: String,
    pub new_findings: Vec<Finding>,
    pub resolved_count: usize,
    pub total_current: usize,
    pub total_baseline: usize,
    pub score_delta: i64,
}

// ---------------------------------------------------------------------------
// Baseline persistence
// ---------------------------------------------------------------------------

/// Default baseline file name.
pub const BASELINE_FILE: &str = ".chaffra-baseline.json";

/// Save findings to a baseline JSON file.
pub fn save_baseline(findings: &[Finding], path: &Path) -> Result<()> {
    let baseline = Baseline {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_owned()),
        findings: findings.iter().map(BaselineFinding::from_finding).collect(),
    };
    let json = serde_json::to_string_pretty(&baseline)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Load a baseline from a JSON file.
pub fn load_baseline(path: &Path) -> Result<Baseline> {
    let content = std::fs::read_to_string(path)?;
    let baseline: Baseline = serde_json::from_str(&content)?;
    Ok(baseline)
}

// ---------------------------------------------------------------------------
// Comparison logic
// ---------------------------------------------------------------------------

/// Compare current findings against a baseline and produce an audit report.
pub fn compare_findings(
    current: &[Finding],
    baseline: &Baseline,
    gate_mode: GateMode,
    warn_threshold: usize,
    fail_threshold: usize,
) -> AuditReport {
    let baseline_set: std::collections::HashSet<BaselineFinding> =
        baseline.findings.iter().cloned().collect();

    let new_findings: Vec<Finding> = current
        .iter()
        .filter(|f| !baseline_set.contains(&BaselineFinding::from_finding(f)))
        .cloned()
        .collect();

    let current_set: std::collections::HashSet<BaselineFinding> =
        current.iter().map(BaselineFinding::from_finding).collect();

    let resolved_count = baseline
        .findings
        .iter()
        .filter(|bf| !current_set.contains(bf))
        .count();

    let relevant_count = match gate_mode {
        GateMode::NewOnly => new_findings.len(),
        GateMode::All => current.len(),
    };

    let score_delta = current.len() as i64 - baseline.findings.len() as i64;

    let verdict = if relevant_count >= fail_threshold && fail_threshold > 0 {
        Verdict::Fail
    } else if relevant_count >= warn_threshold && warn_threshold > 0 {
        Verdict::Warn
    } else {
        Verdict::Pass
    };

    AuditReport {
        verdict,
        gate_mode: match gate_mode {
            GateMode::NewOnly => "new-only",
            GateMode::All => "all",
        }
        .to_owned(),
        new_findings,
        resolved_count,
        total_current: current.len(),
        total_baseline: baseline.findings.len(),
        score_delta,
    }
}

// ---------------------------------------------------------------------------
// AnalysisModule implementation
// ---------------------------------------------------------------------------

/// Audit analysis module.
pub struct AuditModule;

impl AuditModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AuditModule {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisModule for AuditModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "audit".to_owned(),
            name: "PR Audit & Gating".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec![
                "go".to_owned(),
                "python".to_owned(),
                "php".to_owned(),
                "dart".to_owned(),
                "csharp".to_owned(),
                "rust".to_owned(),
            ],
            capabilities: vec!["analyze".to_owned(), "explain".to_owned()],
            rules: vec![
                Rule {
                    id: "new-finding".to_owned(),
                    name: "New finding".to_owned(),
                    description: "A finding not present in the baseline".to_owned(),
                    default_severity: Severity::Warning,
                    category: "audit".to_owned(),
                },
                Rule {
                    id: "score-regression".to_owned(),
                    name: "Score regression".to_owned(),
                    description: "Total finding count increased compared to baseline".to_owned(),
                    default_severity: Severity::Warning,
                    category: "audit".to_owned(),
                },
                Rule {
                    id: "threshold-exceeded".to_owned(),
                    name: "Threshold exceeded".to_owned(),
                    description: "Finding count exceeds the configured gate threshold".to_owned(),
                    default_severity: Severity::Error,
                    category: "audit".to_owned(),
                },
            ],
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        let gate_mode = config
            .get("gate-mode")
            .and_then(|v| GateMode::from_str_loose(v))
            .unwrap_or(GateMode::NewOnly);

        let warn_threshold: usize = config
            .get("warn-threshold")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let fail_threshold: usize = config
            .get("fail-threshold")
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let baseline_path = config
            .get("baseline")
            .cloned()
            .unwrap_or_else(|| BASELINE_FILE.to_owned());

        let bp = Path::new(&baseline_path);
        if bp.is_absolute()
            || bp
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(ChaffraError::Config(format!(
                "baseline path must be relative and within the project directory: {baseline_path}"
            )));
        }

        // Load baseline (empty if not found).
        let baseline = load_baseline(bp).unwrap_or(Baseline {
            timestamp: "none".to_owned(),
            findings: Vec::new(),
        });

        // The audit module receives findings via file content encoded as JSON.
        // Each file's content is expected to be JSON-encoded findings from other modules.
        // If no JSON findings are provided, we produce a pass verdict with no findings.
        let mut current_findings: Vec<Finding> = Vec::new();
        for file in files {
            if file.path.ends_with(".json") {
                match serde_json::from_slice::<Vec<Finding>>(&file.content) {
                    Ok(findings) => current_findings.extend(findings),
                    Err(e) => eprintln!("warning: failed to parse {}: {e}", file.path),
                }
            }
        }

        let report = compare_findings(
            &current_findings,
            &baseline,
            gate_mode,
            warn_threshold,
            fail_threshold,
        );

        let mut findings = Vec::new();

        // Emit a finding for each new issue.
        for new_f in &report.new_findings {
            findings.push(Finding {
                rule_id: "new-finding".to_owned(),
                message: format!(
                    "new issue: {} in {} at line {}",
                    new_f.rule_id, new_f.location.file, new_f.location.start_line
                ),
                severity: Severity::Warning,
                location: new_f.location.clone(),
                confidence: 1.0,
                actions: vec![],
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("original_rule".to_owned(), new_f.rule_id.clone());
                    m
                },
            });
        }

        // Emit score-regression if applicable.
        if report.score_delta > 0 {
            findings.push(Finding {
                rule_id: "score-regression".to_owned(),
                message: format!(
                    "finding count increased by {} (baseline: {}, current: {})",
                    report.score_delta, report.total_baseline, report.total_current
                ),
                severity: Severity::Warning,
                location: Location {
                    file: baseline_path.clone(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }

        // Emit threshold-exceeded if verdict is fail.
        if report.verdict == Verdict::Fail {
            let relevant = match gate_mode {
                GateMode::NewOnly => report.new_findings.len(),
                GateMode::All => report.total_current,
            };
            findings.push(Finding {
                rule_id: "threshold-exceeded".to_owned(),
                message: format!(
                    "audit verdict: FAIL ({relevant} relevant findings exceed threshold {fail_threshold})"
                ),
                severity: Severity::Error,
                location: Location {
                    file: baseline_path.clone(),
                    start_line: 1,
                    end_line: 1,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("verdict".to_owned(), report.verdict.to_string());
                    m
                },
            });
        }

        Ok(AnalysisResult {
            findings,
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: {
                    let mut c = HashMap::new();
                    c.insert("new_findings".to_owned(), report.new_findings.len() as u64);
                    c.insert("resolved".to_owned(), report.resolved_count as u64);
                    c.insert("total_current".to_owned(), report.total_current as u64);
                    c.insert("total_baseline".to_owned(), report.total_baseline as u64);
                    c
                },
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "new-finding" => Ok(RuleExplanation {
                rule_id: "new-finding".to_owned(),
                name: "New finding".to_owned(),
                description: "A diagnostic finding that was not present in the stored baseline. This means the current change introduces a new issue.".to_owned(),
                rationale: "Tracking new findings prevents regressions. Only new issues introduced by a PR are flagged, so existing tech debt does not block progress.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore new-finding".to_owned(),
                examples: vec![
                    "A PR adds an unused import that was not in the baseline.".to_owned(),
                ],
            }),
            "score-regression" => Ok(RuleExplanation {
                rule_id: "score-regression".to_owned(),
                name: "Score regression".to_owned(),
                description: "The total number of findings increased compared to the baseline snapshot.".to_owned(),
                rationale: "Even if individual findings are individually minor, a growing total count signals declining code quality.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "// chaffra:ignore score-regression".to_owned(),
                examples: vec![],
            }),
            "threshold-exceeded" => Ok(RuleExplanation {
                rule_id: "threshold-exceeded".to_owned(),
                name: "Threshold exceeded".to_owned(),
                description: "The number of relevant findings exceeds the configured fail threshold, causing the audit to fail.".to_owned(),
                rationale: "Hard thresholds enforce quality gates in CI. A PR that introduces too many issues is blocked until they are resolved.".to_owned(),
                default_severity: Severity::Error,
                suppression_syntax: "// chaffra:ignore threshold-exceeded".to_owned(),
                examples: vec![
                    "fail-threshold=5 and the PR introduces 7 new findings.".to_owned(),
                ],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, _findings: &[Finding], _dry_run: bool) -> Result<Vec<FixResult>> {
        // Audit issues cannot be auto-fixed.
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(rule_id: &str, file: &str, line: u32, message: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_owned(),
            message: message.to_owned(),
            severity: Severity::Warning,
            location: Location {
                file: file.to_owned(),
                start_line: line,
                end_line: line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        }
    }

    fn make_baseline(findings: &[Finding]) -> Baseline {
        Baseline {
            timestamp: "test".to_owned(),
            findings: findings.iter().map(BaselineFinding::from_finding).collect(),
        }
    }

    // --- Verdict display ---

    #[test]
    fn test_verdict_display() {
        assert_eq!(Verdict::Pass.to_string(), "pass");
        assert_eq!(Verdict::Warn.to_string(), "warn");
        assert_eq!(Verdict::Fail.to_string(), "fail");
    }

    // --- GateMode parsing ---

    #[test]
    fn test_gate_mode_from_str() {
        let cases = vec![
            ("new-only", Some(GateMode::NewOnly)),
            ("newonly", Some(GateMode::NewOnly)),
            ("new", Some(GateMode::NewOnly)),
            ("NEW-ONLY", Some(GateMode::NewOnly)),
            ("new_only", Some(GateMode::NewOnly)),
            ("all", Some(GateMode::All)),
            ("ALL", Some(GateMode::All)),
            ("bogus", None),
        ];
        for (input, expected) in cases {
            assert_eq!(GateMode::from_str_loose(input), expected, "input: {input}");
        }
    }

    // --- BaselineFinding ---

    #[test]
    fn test_baseline_finding_from_finding() {
        let f = make_finding("unused-function", "main.go", 5, "function foo is unused");
        let bf = BaselineFinding::from_finding(&f);
        assert_eq!(bf.rule_id, "unused-function");
        assert_eq!(bf.file, "main.go");
        assert_eq!(bf.start_line, 5);
    }

    // --- Comparison logic ---

    #[test]
    fn test_compare_no_baseline_all_new() {
        let findings = vec![
            make_finding("unused-function", "a.go", 1, "unused func"),
            make_finding("unused-import", "b.go", 2, "unused import"),
        ];
        let baseline = Baseline {
            timestamp: "test".to_owned(),
            findings: Vec::new(),
        };

        let report = compare_findings(&findings, &baseline, GateMode::NewOnly, 1, 5);
        assert_eq!(report.new_findings.len(), 2);
        assert_eq!(report.resolved_count, 0);
        assert_eq!(report.total_current, 2);
        assert_eq!(report.total_baseline, 0);
        assert_eq!(report.score_delta, 2);
        assert_eq!(report.verdict, Verdict::Warn);
    }

    #[test]
    fn test_compare_same_findings_pass() {
        let findings = vec![make_finding("unused-function", "a.go", 1, "unused func")];
        let baseline = make_baseline(&findings);

        let report = compare_findings(&findings, &baseline, GateMode::NewOnly, 1, 5);
        assert_eq!(report.new_findings.len(), 0);
        assert_eq!(report.resolved_count, 0);
        assert_eq!(report.verdict, Verdict::Pass);
    }

    #[test]
    fn test_compare_resolved_findings() {
        let baseline_findings = vec![
            make_finding("unused-function", "a.go", 1, "unused func"),
            make_finding("unused-import", "b.go", 2, "unused import"),
        ];
        let current = vec![make_finding("unused-function", "a.go", 1, "unused func")];
        let baseline = make_baseline(&baseline_findings);

        let report = compare_findings(&current, &baseline, GateMode::NewOnly, 1, 5);
        assert_eq!(report.resolved_count, 1);
        assert_eq!(report.score_delta, -1);
        assert_eq!(report.verdict, Verdict::Pass);
    }

    #[test]
    fn test_compare_fail_threshold() {
        let findings: Vec<Finding> = (0..6)
            .map(|i| make_finding("issue", "f.go", i, &format!("issue {i}")))
            .collect();
        let baseline = Baseline {
            timestamp: "test".to_owned(),
            findings: Vec::new(),
        };

        let report = compare_findings(&findings, &baseline, GateMode::NewOnly, 1, 5);
        assert_eq!(report.verdict, Verdict::Fail);
    }

    #[test]
    fn test_compare_all_mode_counts_everything() {
        let findings = vec![
            make_finding("old", "a.go", 1, "old issue"),
            make_finding("new", "b.go", 2, "new issue"),
        ];
        let baseline = make_baseline(&[make_finding("old", "a.go", 1, "old issue")]);

        let report = compare_findings(&findings, &baseline, GateMode::All, 1, 5);
        // All mode counts both findings.
        assert_eq!(report.verdict, Verdict::Warn);
    }

    #[test]
    fn test_compare_zero_thresholds() {
        let findings = vec![make_finding("issue", "a.go", 1, "issue")];
        let baseline = Baseline {
            timestamp: "test".to_owned(),
            findings: Vec::new(),
        };

        // Zero thresholds disable the gate level.
        let report = compare_findings(&findings, &baseline, GateMode::NewOnly, 0, 0);
        assert_eq!(report.verdict, Verdict::Pass);
    }

    // --- Baseline persistence ---

    #[test]
    fn test_save_and_load_baseline() {
        let dir = std::env::temp_dir().join("chaffra_audit_test_baseline");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(BASELINE_FILE);

        let findings = vec![make_finding("unused", "a.go", 1, "unused func")];
        save_baseline(&findings, &path).unwrap();

        let loaded = load_baseline(&path).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings[0].rule_id, "unused");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_baseline_missing_file() {
        let result = load_baseline(Path::new("/nonexistent/baseline.json"));
        assert!(result.is_err());
    }

    // --- Module describe ---

    #[test]
    fn test_describe() {
        let module = AuditModule::new();
        let info = module.describe();
        assert_eq!(info.id, "audit");
        assert_eq!(info.rules.len(), 3);
        let rule_ids: Vec<&str> = info.rules.iter().map(|r| r.id.as_str()).collect();
        assert!(rule_ids.contains(&"new-finding"));
        assert!(rule_ids.contains(&"score-regression"));
        assert!(rule_ids.contains(&"threshold-exceeded"));
    }

    #[test]
    fn test_default_module() {
        let module = AuditModule;
        assert_eq!(module.describe().id, "audit");
    }

    // --- Module explain ---

    #[test]
    fn test_explain_all_rules() {
        let module = AuditModule::new();
        for rule_id in ["new-finding", "score-regression", "threshold-exceeded"] {
            let explanation = module.explain(rule_id).unwrap();
            assert_eq!(explanation.rule_id, rule_id);
            assert!(!explanation.description.is_empty());
        }
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = AuditModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    // --- Module analyze ---

    #[test]
    fn test_analyze_no_baseline_no_findings() {
        let module = AuditModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_with_json_findings() {
        let module = AuditModule::new();
        let findings_json = serde_json::to_vec(&vec![make_finding(
            "unused-function",
            "a.go",
            1,
            "unused func",
        )])
        .unwrap();

        let files = vec![FileInfo {
            path: "findings.json".to_owned(),
            content: findings_json,
        }];

        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let new_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "new-finding")
            .collect();
        assert_eq!(new_findings.len(), 1);
    }

    #[test]
    fn test_analyze_score_regression() {
        let module = AuditModule::new();
        let findings_json = serde_json::to_vec(&vec![
            make_finding("issue-1", "a.go", 1, "issue one"),
            make_finding("issue-2", "b.go", 2, "issue two"),
        ])
        .unwrap();

        let files = vec![FileInfo {
            path: "findings.json".to_owned(),
            content: findings_json,
        }];

        let result = module.analyze(&files, &HashMap::new()).unwrap();
        let regression: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "score-regression")
            .collect();
        assert_eq!(regression.len(), 1);
    }

    #[test]
    fn test_analyze_with_fail_threshold() {
        let module = AuditModule::new();
        let many_findings: Vec<Finding> = (0..6)
            .map(|i| make_finding("issue", &format!("f{i}.go"), i, &format!("issue {i}")))
            .collect();
        let findings_json = serde_json::to_vec(&many_findings).unwrap();

        let files = vec![FileInfo {
            path: "findings.json".to_owned(),
            content: findings_json,
        }];

        let mut config = HashMap::new();
        config.insert("fail-threshold".to_owned(), "5".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        let threshold: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "threshold-exceeded")
            .collect();
        assert_eq!(threshold.len(), 1);
    }

    // --- Module fix ---

    #[test]
    fn test_fix_returns_empty() {
        let module = AuditModule::new();
        let results = module.fix(&[], false).unwrap();
        assert!(results.is_empty());
    }

    // --- Config parsing ---

    #[test]
    fn test_analyze_gate_mode_all() {
        let module = AuditModule::new();
        let mut config = HashMap::new();
        config.insert("gate-mode".to_owned(), "all".to_owned());
        config.insert("warn-threshold".to_owned(), "1".to_owned());

        let findings_json =
            serde_json::to_vec(&vec![make_finding("old", "a.go", 1, "old issue")]).unwrap();
        let files = vec![FileInfo {
            path: "findings.json".to_owned(),
            content: findings_json,
        }];

        let result = module.analyze(&files, &config).unwrap();
        // In all mode with warn-threshold=1, we should get findings.
        assert!(!result.findings.is_empty());
    }

    // --- Non-JSON files are skipped ---

    #[test]
    fn test_analyze_skips_non_json() {
        let module = AuditModule::new();
        let files = vec![FileInfo {
            path: "main.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_baseline_path_traversal_rejected() {
        let module = AuditModule::new();
        let mut config = HashMap::new();
        config.insert("baseline".to_owned(), "../../.env".to_owned());
        let result = module.analyze(&[], &config);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("relative"));
    }

    #[test]
    fn test_baseline_absolute_path_rejected() {
        let module = AuditModule::new();
        let mut config = HashMap::new();
        config.insert("baseline".to_owned(), "/etc/passwd".to_owned());
        let result = module.analyze(&[], &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_gate_mode_serialization_matches_serde() {
        let report = compare_findings(
            &[],
            &Baseline {
                timestamp: "test".to_owned(),
                findings: Vec::new(),
            },
            GateMode::NewOnly,
            1,
            5,
        );
        assert_eq!(report.gate_mode, "new-only");

        let report = compare_findings(
            &[],
            &Baseline {
                timestamp: "test".to_owned(),
                findings: Vec::new(),
            },
            GateMode::All,
            1,
            5,
        );
        assert_eq!(report.gate_mode, "all");
    }

    #[test]
    fn test_threshold_exceeded_uses_correct_count_in_all_mode() {
        let module = AuditModule::new();
        let many_findings: Vec<Finding> = (0..6)
            .map(|i| make_finding("issue", &format!("f{i}.go"), i, &format!("issue {i}")))
            .collect();
        let findings_json = serde_json::to_vec(&many_findings).unwrap();
        let files = vec![FileInfo {
            path: "findings.json".to_owned(),
            content: findings_json,
        }];
        let mut config = HashMap::new();
        config.insert("gate-mode".to_owned(), "all".to_owned());
        config.insert("fail-threshold".to_owned(), "5".to_owned());

        let result = module.analyze(&files, &config).unwrap();
        let threshold: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.rule_id == "threshold-exceeded")
            .collect();
        assert_eq!(threshold.len(), 1);
        assert!(
            threshold[0].message.contains("6 relevant"),
            "should report total_current (6) in All mode, got: {}",
            threshold[0].message
        );
    }

    #[test]
    fn test_save_baseline_has_real_timestamp() {
        let dir = std::env::temp_dir().join("chaffra_audit_test_ts");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(BASELINE_FILE);

        save_baseline(&[], &path).unwrap();
        let loaded = load_baseline(&path).unwrap();
        assert_ne!(loaded.timestamp, "now");
        assert!(loaded.timestamp.parse::<u64>().is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
