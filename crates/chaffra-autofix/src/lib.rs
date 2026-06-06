//! Automated fix orchestration for chaffra.
//!
//! Collects fixable findings from analysis modules, detects conflicts (overlapping
//! edits), and applies safe text edits atomically per file. Supports dry-run preview,
//! rule-specific filtering, and transaction semantics (apply-or-skip per file).

pub mod conflict;
pub mod engine;
pub mod hooks;

use chaffra_core::diagnostic::{
    AnalysisResult, FileInfo, Finding, FixResult, ModuleInfo, ModuleMetrics, Rule, RuleExplanation,
    Severity, TextEdit,
};
use chaffra_core::error::{ChaffraError, Result};
use chaffra_core::module::AnalysisModule;
use std::collections::HashMap;

use conflict::detect_conflicts;
use engine::{apply_edits_to_content, plan_edits};

/// Autofix analysis module.
///
/// This module does not produce its own findings. It collects fixable findings
/// from other modules and orchestrates their application.
pub struct AutofixModule;

impl AutofixModule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AutofixModule {
    fn default() -> Self {
        Self::new()
    }
}

/// Rules provided by this module.
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "fix-applied",
        "Fix applied",
        "An automated fix was successfully applied",
        "autofix",
    ),
    (
        "fix-conflict",
        "Fix conflict",
        "Overlapping edits detected; both skipped to avoid corruption",
        "autofix",
    ),
    (
        "fix-skipped",
        "Fix skipped",
        "Finding has no auto-fixable action",
        "autofix",
    ),
];

impl AnalysisModule for AutofixModule {
    fn describe(&self) -> ModuleInfo {
        ModuleInfo {
            id: "autofix".to_owned(),
            name: "Automated Fix Orchestration".to_owned(),
            version: "0.1.0".to_owned(),
            languages: vec!["go".to_owned(), "python".to_owned()],
            capabilities: vec!["fix".to_owned(), "explain".to_owned()],
            rules: RULES
                .iter()
                .map(|(id, name, desc, cat)| Rule {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    description: (*desc).to_owned(),
                    default_severity: Severity::Info,
                    category: (*cat).to_owned(),
                })
                .collect(),
        }
    }

    fn analyze(
        &self,
        files: &[FileInfo],
        _config: &HashMap<String, String>,
    ) -> Result<AnalysisResult> {
        // Autofix does not produce its own findings during analysis.
        Ok(AnalysisResult {
            findings: vec![],
            metrics: ModuleMetrics {
                files_analyzed: files.len() as u64,
                duration_ms: 0,
                counters: HashMap::new(),
                ..Default::default()
            },
        })
    }

    fn explain(&self, rule_id: &str) -> Result<RuleExplanation> {
        match rule_id {
            "fix-applied" => Ok(RuleExplanation {
                rule_id: "fix-applied".to_owned(),
                name: "Fix applied".to_owned(),
                description: "An automated fix was successfully applied to the source file."
                    .to_owned(),
                rationale: "Tracks which fixes were applied for audit trail purposes.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "N/A".to_owned(),
                examples: vec![],
            }),
            "fix-conflict" => Ok(RuleExplanation {
                rule_id: "fix-conflict".to_owned(),
                name: "Fix conflict".to_owned(),
                description:
                    "Two or more fixes target overlapping line ranges in the same file. Both are skipped to avoid corrupting the source."
                        .to_owned(),
                rationale: "Applying overlapping edits would produce unpredictable results. Skipping both preserves correctness.".to_owned(),
                default_severity: Severity::Warning,
                suppression_syntax: "N/A".to_owned(),
                examples: vec![
                    "Fix A removes lines 5-10, Fix B removes lines 8-12 -> both skipped"
                        .to_owned(),
                ],
            }),
            "fix-skipped" => Ok(RuleExplanation {
                rule_id: "fix-skipped".to_owned(),
                name: "Fix skipped".to_owned(),
                description: "The finding has no auto-fixable action available.".to_owned(),
                rationale: "Not all findings can be automatically fixed. Manual intervention is required.".to_owned(),
                default_severity: Severity::Info,
                suppression_syntax: "N/A".to_owned(),
                examples: vec![],
            }),
            _ => Err(ChaffraError::RuleNotFound(rule_id.to_owned())),
        }
    }

    fn fix(&self, findings: &[Finding], dry_run: bool) -> Result<Vec<FixResult>> {
        orchestrate_fixes(findings, dry_run)
    }
}

/// Filter findings to only those with auto-fixable actions.
pub fn collect_fixable(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| f.actions.iter().any(|a| a.auto_fixable))
        .collect()
}

/// Filter findings by a specific rule ID.
pub fn filter_by_rule<'a>(findings: &'a [Finding], rule_id: &str) -> Vec<&'a Finding> {
    findings.iter().filter(|f| f.rule_id == rule_id).collect()
}

/// Orchestrate fix application across all findings.
///
/// Groups edits by file, detects conflicts within each file, and applies
/// non-conflicting edits atomically. Returns a `FixResult` for each input finding.
pub fn orchestrate_fixes(findings: &[Finding], dry_run: bool) -> Result<Vec<FixResult>> {
    let mut results = Vec::new();

    // Collect all edits, grouped by file.
    let planned = plan_edits(findings);

    // Detect conflicts per file.
    let conflicts = detect_conflicts(&planned);

    for (i, finding) in findings.iter().enumerate() {
        let fixable_action = finding.actions.iter().find(|a| a.auto_fixable);
        let action = match fixable_action {
            Some(a) => a,
            None => {
                results.push(FixResult {
                    rule_id: finding.rule_id.clone(),
                    applied: false,
                    edits: vec![],
                    reason: "no auto-fix available".to_owned(),
                });
                continue;
            }
        };

        // Check if any edit from this finding is in a conflict.
        let has_conflict = conflicts.contains(&i);

        if has_conflict {
            results.push(FixResult {
                rule_id: finding.rule_id.clone(),
                applied: false,
                edits: action.edits.clone(),
                reason: "overlapping edits detected; skipped to avoid corruption".to_owned(),
            });
        } else if dry_run {
            results.push(FixResult {
                rule_id: finding.rule_id.clone(),
                applied: false,
                edits: action.edits.clone(),
                reason: "dry run".to_owned(),
            });
        } else {
            results.push(FixResult {
                rule_id: finding.rule_id.clone(),
                applied: true,
                edits: action.edits.clone(),
                reason: "applied".to_owned(),
            });
        }
    }

    Ok(results)
}

/// Apply fixes to file contents in memory. Returns a map of file path to new content.
///
/// This is used for actual file writing -- the caller reads file content, passes it here,
/// and writes the result back.
pub fn apply_fixes_to_files(
    file_contents: &HashMap<String, String>,
    results: &[FixResult],
) -> HashMap<String, String> {
    // Collect all edits that were applied, grouped by file.
    let mut edits_by_file: HashMap<String, Vec<&TextEdit>> = HashMap::new();
    for result in results {
        if result.applied {
            for edit in &result.edits {
                edits_by_file
                    .entry(edit.file.clone())
                    .or_default()
                    .push(edit);
            }
        }
    }

    let mut output = HashMap::new();
    for (file, edits) in &edits_by_file {
        if let Some(content) = file_contents.get(file) {
            let new_content = apply_edits_to_content(content, edits);
            output.insert(file.clone(), new_content);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::{Action, Location};

    fn make_finding(rule_id: &str, file: &str, start: u32, end: u32, fixable: bool) -> Finding {
        let edits = if fixable {
            vec![TextEdit {
                file: file.to_owned(),
                start_line: start,
                end_line: end,
                new_text: String::new(),
            }]
        } else {
            vec![]
        };
        let actions = if fixable {
            vec![Action {
                description: format!("Fix {rule_id}"),
                auto_fixable: true,
                edits,
            }]
        } else {
            vec![]
        };
        Finding {
            rule_id: rule_id.to_owned(),
            message: format!("{rule_id} finding"),
            severity: Severity::Warning,
            location: Location {
                file: file.to_owned(),
                start_line: start,
                end_line: end,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_describe() {
        let module = AutofixModule::new();
        let info = module.describe();
        assert_eq!(info.id, "autofix");
        assert_eq!(info.rules.len(), 3);
        assert!(info.capabilities.contains(&"fix".to_owned()));
    }

    #[test]
    fn test_default() {
        let module = AutofixModule::default();
        let info = module.describe();
        assert_eq!(info.id, "autofix");
    }

    #[test]
    fn test_analyze_produces_no_findings() {
        let module = AutofixModule::new();
        let result = module.analyze(&[], &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_analyze_with_files() {
        let module = AutofixModule::new();
        let files = vec![FileInfo {
            path: "test.go".to_owned(),
            content: b"package main".to_vec(),
        }];
        let result = module.analyze(&files, &HashMap::new()).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(result.metrics.files_analyzed, 1);
    }

    #[test]
    fn test_explain_fix_applied() {
        let module = AutofixModule::new();
        let explanation = module.explain("fix-applied").unwrap();
        assert_eq!(explanation.rule_id, "fix-applied");
        assert!(!explanation.description.is_empty());
    }

    #[test]
    fn test_explain_fix_conflict() {
        let module = AutofixModule::new();
        let explanation = module.explain("fix-conflict").unwrap();
        assert_eq!(explanation.rule_id, "fix-conflict");
        assert!(!explanation.examples.is_empty());
    }

    #[test]
    fn test_explain_fix_skipped() {
        let module = AutofixModule::new();
        let explanation = module.explain("fix-skipped").unwrap();
        assert_eq!(explanation.rule_id, "fix-skipped");
    }

    #[test]
    fn test_explain_unknown_rule() {
        let module = AutofixModule::new();
        assert!(module.explain("nonexistent").is_err());
    }

    #[test]
    fn test_collect_fixable() {
        let findings = vec![
            make_finding("unused-function", "a.go", 5, 10, true),
            make_finding("unused-file", "b.go", 1, 1, false),
            make_finding("unused-import", "a.go", 3, 3, true),
        ];
        let fixable = collect_fixable(&findings);
        assert_eq!(fixable.len(), 2);
    }

    #[test]
    fn test_collect_fixable_empty() {
        let fixable = collect_fixable(&[]);
        assert!(fixable.is_empty());
    }

    #[test]
    fn test_filter_by_rule() {
        let findings = vec![
            make_finding("unused-function", "a.go", 5, 10, true),
            make_finding("unused-import", "a.go", 3, 3, true),
            make_finding("unused-function", "b.go", 1, 5, true),
        ];
        let filtered = filter_by_rule(&findings, "unused-function");
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_by_rule_no_match() {
        let findings = vec![make_finding("unused-function", "a.go", 5, 10, true)];
        let filtered = filter_by_rule(&findings, "nonexistent");
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_fix_dry_run() {
        let module = AutofixModule::new();
        let findings = vec![make_finding("unused-function", "a.go", 5, 10, true)];
        let results = module.fix(&findings, true).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
        assert_eq!(results[0].reason, "dry run");
        assert!(!results[0].edits.is_empty());
    }

    #[test]
    fn test_fix_apply() {
        let module = AutofixModule::new();
        let findings = vec![make_finding("unused-function", "a.go", 5, 10, true)];
        let results = module.fix(&findings, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].applied);
        assert_eq!(results[0].reason, "applied");
    }

    #[test]
    fn test_fix_no_action() {
        let module = AutofixModule::new();
        let findings = vec![make_finding("unused-file", "a.go", 1, 1, false)];
        let results = module.fix(&findings, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].applied);
        assert_eq!(results[0].reason, "no auto-fix available");
    }

    #[test]
    fn test_fix_mixed_findings() {
        let module = AutofixModule::new();
        let findings = vec![
            make_finding("unused-function", "a.go", 5, 10, true),
            make_finding("unused-file", "a.go", 1, 1, false),
            make_finding("unused-import", "b.go", 3, 3, true),
        ];
        let results = module.fix(&findings, false).unwrap();
        assert_eq!(results.len(), 3);
        assert!(results[0].applied);
        assert!(!results[1].applied);
        assert!(results[2].applied);
    }

    #[test]
    fn test_orchestrate_with_conflict() {
        // Two findings that overlap in the same file.
        let findings = vec![
            make_finding("rule-a", "a.go", 5, 10, true),
            make_finding("rule-b", "a.go", 8, 12, true),
        ];
        let results = orchestrate_fixes(&findings, false).unwrap();
        assert_eq!(results.len(), 2);
        // Both should be skipped due to conflict.
        assert!(!results[0].applied);
        assert!(!results[1].applied);
        assert!(results[0].reason.contains("overlapping"));
        assert!(results[1].reason.contains("overlapping"));
    }

    #[test]
    fn test_orchestrate_no_conflict() {
        // Two findings that do not overlap.
        let findings = vec![
            make_finding("rule-a", "a.go", 1, 3, true),
            make_finding("rule-b", "a.go", 5, 7, true),
        ];
        let results = orchestrate_fixes(&findings, false).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].applied);
        assert!(results[1].applied);
    }

    #[test]
    fn test_orchestrate_dry_run_with_conflict() {
        // Even in dry run, conflicts are detected.
        let findings = vec![
            make_finding("rule-a", "a.go", 5, 10, true),
            make_finding("rule-b", "a.go", 8, 12, true),
        ];
        let results = orchestrate_fixes(&findings, true).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[0].applied);
        assert!(!results[1].applied);
        // Conflict reason takes priority over dry run reason.
        assert!(results[0].reason.contains("overlapping"));
    }

    #[test]
    fn test_apply_fixes_to_files() {
        let mut file_contents = HashMap::new();
        file_contents.insert(
            "test.go".to_owned(),
            "line1\nline2\nline3\nline4\nline5\n".to_owned(),
        );

        let results = vec![FixResult {
            rule_id: "unused-import".to_owned(),
            applied: true,
            edits: vec![TextEdit {
                file: "test.go".to_owned(),
                start_line: 2,
                end_line: 2,
                new_text: String::new(),
            }],
            reason: "applied".to_owned(),
        }];

        let output = apply_fixes_to_files(&file_contents, &results);
        assert!(output.contains_key("test.go"));
        let new_content = &output["test.go"];
        assert!(!new_content.contains("line2"));
        assert!(new_content.contains("line1"));
        assert!(new_content.contains("line3"));
    }

    #[test]
    fn test_apply_fixes_skips_unapplied() {
        let mut file_contents = HashMap::new();
        file_contents.insert("test.go".to_owned(), "line1\nline2\n".to_owned());

        let results = vec![FixResult {
            rule_id: "unused-import".to_owned(),
            applied: false,
            edits: vec![TextEdit {
                file: "test.go".to_owned(),
                start_line: 2,
                end_line: 2,
                new_text: String::new(),
            }],
            reason: "dry run".to_owned(),
        }];

        let output = apply_fixes_to_files(&file_contents, &results);
        assert!(output.is_empty());
    }

    #[test]
    fn test_apply_fixes_missing_file() {
        let file_contents = HashMap::new();
        let results = vec![FixResult {
            rule_id: "test".to_owned(),
            applied: true,
            edits: vec![TextEdit {
                file: "missing.go".to_owned(),
                start_line: 1,
                end_line: 1,
                new_text: String::new(),
            }],
            reason: "applied".to_owned(),
        }];

        let output = apply_fixes_to_files(&file_contents, &results);
        assert!(output.is_empty());
    }

    #[test]
    fn test_apply_fixes_replacement() {
        let mut file_contents = HashMap::new();
        file_contents.insert("test.go".to_owned(), "line1\nold_line\nline3\n".to_owned());

        let results = vec![FixResult {
            rule_id: "test".to_owned(),
            applied: true,
            edits: vec![TextEdit {
                file: "test.go".to_owned(),
                start_line: 2,
                end_line: 2,
                new_text: "new_line\n".to_owned(),
            }],
            reason: "applied".to_owned(),
        }];

        let output = apply_fixes_to_files(&file_contents, &results);
        let content = &output["test.go"];
        assert!(content.contains("new_line"));
        assert!(!content.contains("old_line"));
    }

    #[test]
    fn test_apply_fixes_multiple_files() {
        let mut file_contents = HashMap::new();
        file_contents.insert("a.go".to_owned(), "a1\na2\na3\n".to_owned());
        file_contents.insert("b.go".to_owned(), "b1\nb2\nb3\n".to_owned());

        let results = vec![
            FixResult {
                rule_id: "test".to_owned(),
                applied: true,
                edits: vec![TextEdit {
                    file: "a.go".to_owned(),
                    start_line: 2,
                    end_line: 2,
                    new_text: String::new(),
                }],
                reason: "applied".to_owned(),
            },
            FixResult {
                rule_id: "test".to_owned(),
                applied: true,
                edits: vec![TextEdit {
                    file: "b.go".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    new_text: String::new(),
                }],
                reason: "applied".to_owned(),
            },
        ];

        let output = apply_fixes_to_files(&file_contents, &results);
        assert_eq!(output.len(), 2);
        assert!(!output["a.go"].contains("a2"));
        assert!(!output["b.go"].contains("b1"));
    }
}
