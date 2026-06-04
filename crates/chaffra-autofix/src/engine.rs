//! Fix application engine.
//!
//! Converts findings into planned edits, applies edits to file content, and
//! handles the mechanics of line-based text manipulation. Edits are applied
//! in reverse line order to preserve line numbers for subsequent edits.

use chaffra_core::diagnostic::{Finding, TextEdit};

/// A planned edit tied back to its originating finding.
#[derive(Debug, Clone)]
pub struct PlannedEdit {
    /// Index of the finding in the original findings slice.
    pub finding_index: usize,
    /// Target file path.
    pub file: String,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Replacement text (empty string means deletion).
    pub new_text: String,
}

/// Extract all planned edits from findings.
///
/// Each fixable action's edits are flattened into individual `PlannedEdit` entries
/// with back-references to the finding index.
pub fn plan_edits(findings: &[Finding]) -> Vec<PlannedEdit> {
    let mut planned = Vec::new();

    for (i, finding) in findings.iter().enumerate() {
        for action in &finding.actions {
            if !action.auto_fixable {
                continue;
            }
            for edit in &action.edits {
                planned.push(PlannedEdit {
                    finding_index: i,
                    file: edit.file.clone(),
                    start_line: edit.start_line,
                    end_line: edit.end_line,
                    new_text: edit.new_text.clone(),
                });
            }
        }
    }

    planned
}

/// Apply a set of text edits to file content.
///
/// Edits are applied in reverse line order so that line numbers remain valid
/// as content is modified. This function operates on a single file's content.
pub fn apply_edits_to_content(content: &str, edits: &[&TextEdit]) -> String {
    let mut lines: Vec<&str> = content.lines().collect();

    // Sort edits by start_line descending so we apply from bottom to top.
    let mut sorted_edits: Vec<&&TextEdit> = edits.iter().collect();
    sorted_edits.sort_by_key(|e| std::cmp::Reverse(e.start_line));

    for edit in sorted_edits {
        let start = (edit.start_line as usize).saturating_sub(1);
        let end = (edit.end_line as usize).min(lines.len());

        if start >= lines.len() {
            continue;
        }

        if edit.new_text.is_empty() {
            // Deletion: remove lines.
            lines.drain(start..end);
        } else {
            // Replacement: replace the range with new text lines.
            let new_lines: Vec<&str> = edit.new_text.lines().collect();
            lines.splice(start..end, new_lines);
        }
    }

    if lines.is_empty() {
        String::new()
    } else {
        let mut result = lines.join("\n");
        // Preserve trailing newline if original had one.
        if content.ends_with('\n') {
            result.push('\n');
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::{Action, Finding, Location, Severity, TextEdit};
    use std::collections::HashMap;

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
    fn test_plan_edits_empty() {
        let planned = plan_edits(&[]);
        assert!(planned.is_empty());
    }

    #[test]
    fn test_plan_edits_fixable() {
        let findings = vec![
            make_finding("rule-a", "a.go", 5, 10, true),
            make_finding("rule-b", "b.go", 1, 3, true),
        ];
        let planned = plan_edits(&findings);
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].finding_index, 0);
        assert_eq!(planned[0].file, "a.go");
        assert_eq!(planned[1].finding_index, 1);
    }

    #[test]
    fn test_plan_edits_skips_non_fixable() {
        let findings = vec![
            make_finding("rule-a", "a.go", 5, 10, true),
            make_finding("rule-b", "b.go", 1, 3, false),
        ];
        let planned = plan_edits(&findings);
        assert_eq!(planned.len(), 1);
        assert_eq!(planned[0].finding_index, 0);
    }

    #[test]
    fn test_plan_edits_multiple_actions() {
        let mut finding = make_finding("rule-a", "a.go", 5, 10, true);
        finding.actions.push(Action {
            description: "Second fix".to_owned(),
            auto_fixable: true,
            edits: vec![TextEdit {
                file: "a.go".to_owned(),
                start_line: 15,
                end_line: 20,
                new_text: String::new(),
            }],
        });
        let planned = plan_edits(&[finding]);
        assert_eq!(planned.len(), 2);
    }

    #[test]
    fn test_apply_delete_single_line() {
        let content = "line1\nline2\nline3\nline4\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 2,
            new_text: String::new(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "line1\nline3\nline4\n");
    }

    #[test]
    fn test_apply_delete_range() {
        let content = "line1\nline2\nline3\nline4\nline5\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 4,
            new_text: String::new(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "line1\nline5\n");
    }

    #[test]
    fn test_apply_replacement() {
        let content = "line1\nold_line\nline3\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 2,
            new_text: "new_line".to_owned(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "line1\nnew_line\nline3\n");
    }

    #[test]
    fn test_apply_multiple_edits_reverse_order() {
        let content = "line1\nline2\nline3\nline4\nline5\n";
        let edit1 = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 2,
            new_text: String::new(),
        };
        let edit2 = TextEdit {
            file: "test.go".to_owned(),
            start_line: 4,
            end_line: 4,
            new_text: String::new(),
        };
        let result = apply_edits_to_content(content, &[&edit1, &edit2]);
        assert_eq!(result, "line1\nline3\nline5\n");
    }

    #[test]
    fn test_apply_empty_file() {
        let content = "";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 1,
            end_line: 1,
            new_text: String::new(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_apply_delete_all_lines() {
        let content = "line1\nline2\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 1,
            end_line: 2,
            new_text: String::new(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_apply_out_of_bounds() {
        let content = "line1\nline2\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 100,
            end_line: 100,
            new_text: String::new(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "line1\nline2\n");
    }

    #[test]
    fn test_apply_multi_line_replacement() {
        let content = "line1\nline2\nline3\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 2,
            new_text: "new_a\nnew_b".to_owned(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert_eq!(result, "line1\nnew_a\nnew_b\nline3\n");
    }

    #[test]
    fn test_preserves_trailing_newline() {
        let content = "line1\nline2\n";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 2,
            new_text: "replaced".to_owned(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert!(result.ends_with('\n'));
    }

    #[test]
    fn test_no_trailing_newline() {
        let content = "line1\nline2";
        let edit = TextEdit {
            file: "test.go".to_owned(),
            start_line: 2,
            end_line: 2,
            new_text: "replaced".to_owned(),
        };
        let result = apply_edits_to_content(content, &[&edit]);
        assert!(!result.ends_with('\n'));
    }
}
