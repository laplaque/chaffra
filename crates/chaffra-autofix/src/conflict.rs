//! Conflict detection for overlapping text edits.
//!
//! When multiple findings target overlapping line ranges in the same file,
//! applying both would corrupt the source. This module detects such conflicts
//! and returns the indices of all conflicting findings so they can be skipped.

use std::collections::HashSet;

use crate::engine::PlannedEdit;

/// Detect conflicts among planned edits.
///
/// Returns the set of finding indices that participate in at least one conflict.
/// Two edits conflict if they target the same file and their line ranges overlap.
pub fn detect_conflicts(planned: &[PlannedEdit]) -> HashSet<usize> {
    let mut conflicting = HashSet::new();

    for i in 0..planned.len() {
        for j in (i + 1)..planned.len() {
            if edits_overlap(&planned[i], &planned[j]) {
                conflicting.insert(planned[i].finding_index);
                conflicting.insert(planned[j].finding_index);
            }
        }
    }

    conflicting
}

/// Check whether two planned edits overlap.
fn edits_overlap(a: &PlannedEdit, b: &PlannedEdit) -> bool {
    if a.file != b.file {
        return false;
    }
    // Ranges overlap if one starts before the other ends.
    a.start_line <= b.end_line && b.start_line <= a.end_line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(file: &str, start: u32, end: u32, idx: usize) -> PlannedEdit {
        PlannedEdit {
            finding_index: idx,
            file: file.to_owned(),
            start_line: start,
            end_line: end,
            new_text: String::new(),
        }
    }

    #[test]
    fn test_no_conflicts_empty() {
        let conflicts = detect_conflicts(&[]);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_no_conflicts_different_files() {
        let edits = vec![edit("a.go", 1, 5, 0), edit("b.go", 1, 5, 1)];
        let conflicts = detect_conflicts(&edits);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_no_conflicts_adjacent_ranges() {
        let edits = vec![edit("a.go", 1, 3, 0), edit("a.go", 4, 6, 1)];
        let conflicts = detect_conflicts(&edits);
        assert!(conflicts.is_empty());
    }

    #[test]
    fn test_overlap_same_line() {
        let edits = vec![edit("a.go", 5, 5, 0), edit("a.go", 5, 5, 1)];
        let conflicts = detect_conflicts(&edits);
        assert!(conflicts.contains(&0));
        assert!(conflicts.contains(&1));
    }

    #[test]
    fn test_overlap_partial() {
        let edits = vec![edit("a.go", 5, 10, 0), edit("a.go", 8, 12, 1)];
        let conflicts = detect_conflicts(&edits);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.contains(&0));
        assert!(conflicts.contains(&1));
    }

    #[test]
    fn test_overlap_nested() {
        let edits = vec![edit("a.go", 1, 20, 0), edit("a.go", 5, 10, 1)];
        let conflicts = detect_conflicts(&edits);
        assert!(conflicts.contains(&0));
        assert!(conflicts.contains(&1));
    }

    #[test]
    fn test_overlap_touching_boundary() {
        // Ranges [1,3] and [3,5] overlap because line 3 is in both.
        let edits = vec![edit("a.go", 1, 3, 0), edit("a.go", 3, 5, 1)];
        let conflicts = detect_conflicts(&edits);
        assert!(conflicts.contains(&0));
        assert!(conflicts.contains(&1));
    }

    #[test]
    fn test_three_way_conflict() {
        let edits = vec![
            edit("a.go", 1, 5, 0),
            edit("a.go", 3, 7, 1),
            edit("a.go", 6, 10, 2),
        ];
        let conflicts = detect_conflicts(&edits);
        // All three are involved in at least one overlap.
        assert_eq!(conflicts.len(), 3);
    }

    #[test]
    fn test_partial_conflict_with_clean_edit() {
        let edits = vec![
            edit("a.go", 1, 3, 0),
            edit("a.go", 2, 5, 1),
            edit("a.go", 10, 12, 2),
        ];
        let conflicts = detect_conflicts(&edits);
        assert!(conflicts.contains(&0));
        assert!(conflicts.contains(&1));
        assert!(!conflicts.contains(&2));
    }

    #[test]
    fn test_mixed_files_partial_conflict() {
        let edits = vec![
            edit("a.go", 1, 5, 0),
            edit("a.go", 3, 7, 1),
            edit("b.go", 3, 7, 2),
        ];
        let conflicts = detect_conflicts(&edits);
        assert_eq!(conflicts.len(), 2);
        assert!(conflicts.contains(&0));
        assert!(conflicts.contains(&1));
        assert!(!conflicts.contains(&2));
    }
}
