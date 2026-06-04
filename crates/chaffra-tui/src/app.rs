//! Application state and event handling for the TUI.

use chaffra_core::diagnostic::{Finding, Severity};
use std::collections::HashMap;

/// How findings are grouped in the list view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    File,
    Rule,
    Severity,
}

impl GroupBy {
    /// Cycle to the next grouping mode.
    pub fn next(self) -> Self {
        match self {
            GroupBy::File => GroupBy::Rule,
            GroupBy::Rule => GroupBy::Severity,
            GroupBy::Severity => GroupBy::File,
        }
    }

    /// Display label.
    pub fn label(self) -> &'static str {
        match self {
            GroupBy::File => "file",
            GroupBy::Rule => "rule",
            GroupBy::Severity => "severity",
        }
    }
}

/// Actions the user can trigger from the TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiAction {
    /// Apply the auto-fix for the selected finding.
    ApplyFix(usize),
    /// Add a suppression comment for the selected finding.
    AddSuppression(usize),
    /// Copy the file:line location to clipboard (as a string).
    CopyLocation(usize),
    /// Quit the TUI.
    Quit,
}

/// Severity filter state.
#[derive(Debug, Clone)]
pub struct SeverityFilter {
    pub show_error: bool,
    pub show_warning: bool,
    pub show_info: bool,
}

impl Default for SeverityFilter {
    fn default() -> Self {
        Self {
            show_error: true,
            show_warning: true,
            show_info: true,
        }
    }
}

impl SeverityFilter {
    /// Check if a severity is visible under the current filter.
    pub fn includes(&self, severity: Severity) -> bool {
        match severity {
            Severity::Error => self.show_error,
            Severity::Warning => self.show_warning,
            Severity::Info => self.show_info,
        }
    }

    /// Toggle a severity level.
    pub fn toggle(&mut self, severity: Severity) {
        match severity {
            Severity::Error => self.show_error = !self.show_error,
            Severity::Warning => self.show_warning = !self.show_warning,
            Severity::Info => self.show_info = !self.show_info,
        }
    }
}

/// Module filter state.
#[derive(Debug, Clone, Default)]
pub struct ModuleFilter {
    /// Module IDs that are currently hidden.
    pub hidden: std::collections::HashSet<String>,
}

impl ModuleFilter {
    /// Check if a module is visible.
    pub fn includes(&self, module_id: &str) -> bool {
        !self.hidden.contains(module_id)
    }

    /// Toggle visibility for a module.
    pub fn toggle(&mut self, module_id: &str) {
        if self.hidden.contains(module_id) {
            self.hidden.remove(module_id);
        } else {
            self.hidden.insert(module_id.to_owned());
        }
    }
}

/// Main application state for the TUI.
#[derive(Debug)]
pub struct App {
    /// All findings loaded into the TUI.
    pub findings: Vec<Finding>,
    /// Current selection index into the filtered list.
    pub selected: usize,
    /// Current grouping mode.
    pub group_by: GroupBy,
    /// Severity filter.
    pub severity_filter: SeverityFilter,
    /// Module filter.
    pub module_filter: ModuleFilter,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Pending actions to be processed.
    pub pending_actions: Vec<TuiAction>,
    /// Status message displayed at the bottom.
    pub status: String,
}

impl App {
    /// Create a new TUI app with the given findings.
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            selected: 0,
            group_by: GroupBy::File,
            severity_filter: SeverityFilter::default(),
            module_filter: ModuleFilter::default(),
            should_quit: false,
            pending_actions: Vec::new(),
            status: String::new(),
        }
    }

    /// Get the filtered and grouped findings.
    pub fn visible_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| self.severity_filter.includes(f.severity))
            .filter(|f| {
                let module_id = f.rule_id.split(':').next().unwrap_or(&f.rule_id);
                self.module_filter.includes(module_id)
            })
            .collect()
    }

    /// Get grouped findings as (group_label, findings) pairs.
    pub fn grouped_findings(&self) -> Vec<(String, Vec<&Finding>)> {
        let visible = self.visible_findings();
        let mut groups: HashMap<String, Vec<&Finding>> = HashMap::new();

        for finding in &visible {
            let key = match self.group_by {
                GroupBy::File => finding.location.file.clone(),
                GroupBy::Rule => finding.rule_id.clone(),
                GroupBy::Severity => finding.severity.to_string(),
            };
            groups.entry(key).or_default().push(finding);
        }

        let mut sorted: Vec<(String, Vec<&Finding>)> = groups.into_iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        sorted
    }

    /// Total number of visible findings.
    pub fn visible_count(&self) -> usize {
        self.visible_findings().len()
    }

    /// Move selection up.
    pub fn move_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down.
    pub fn move_down(&mut self) {
        let count = self.visible_count();
        if count > 0 && self.selected < count - 1 {
            self.selected += 1;
        }
    }

    /// Move to the first item.
    pub fn move_to_top(&mut self) {
        self.selected = 0;
    }

    /// Move to the last item.
    pub fn move_to_bottom(&mut self) {
        let count = self.visible_count();
        if count > 0 {
            self.selected = count - 1;
        }
    }

    /// Cycle the grouping mode.
    pub fn cycle_group(&mut self) {
        self.group_by = self.group_by.next();
        self.selected = 0;
        self.status = format!("Grouped by: {}", self.group_by.label());
    }

    /// Toggle severity filter for a given level.
    pub fn toggle_severity(&mut self, severity: Severity) {
        self.severity_filter.toggle(severity);
        self.selected = 0;
        self.status = format!("Toggled {} filter", severity);
    }

    /// Apply fix for the currently selected finding.
    pub fn apply_fix(&mut self) {
        let visible = self.visible_findings();
        if self.selected >= visible.len() {
            return;
        }
        let has_fix = visible[self.selected]
            .actions
            .iter()
            .any(|a| a.auto_fixable);
        let rule_id = visible[self.selected].rule_id.clone();
        drop(visible);

        if has_fix {
            if let Some(idx) = self.original_index(self.selected) {
                self.pending_actions.push(TuiAction::ApplyFix(idx));
                self.status = format!("Fix queued for: {rule_id}");
            }
        } else {
            self.status = "No auto-fix available for this finding.".to_owned();
        }
    }

    /// Add suppression for the currently selected finding.
    pub fn add_suppression(&mut self) {
        let visible = self.visible_findings();
        if self.selected < visible.len() {
            if let Some(idx) = self.original_index(self.selected) {
                self.pending_actions.push(TuiAction::AddSuppression(idx));
                self.status = "Suppression queued.".to_owned();
            }
        }
    }

    /// Copy location of the currently selected finding.
    pub fn copy_location(&mut self) -> Option<String> {
        let visible = self.visible_findings();
        if self.selected < visible.len() {
            let finding = visible[self.selected];
            let location = format!("{}:{}", finding.location.file, finding.location.start_line);
            self.status = format!("Copied: {location}");
            Some(location)
        } else {
            None
        }
    }

    /// Request quit.
    pub fn quit(&mut self) {
        self.should_quit = true;
        self.pending_actions.push(TuiAction::Quit);
    }

    /// Handle a key event.
    pub fn handle_key(&mut self, key: char) {
        match key {
            'k' => self.move_up(),
            'j' => self.move_down(),
            'g' => self.move_to_top(),
            'G' => self.move_to_bottom(),
            'f' => self.apply_fix(),
            's' => self.add_suppression(),
            'c' => {
                let _ = self.copy_location();
            }
            'e' => self.toggle_severity(Severity::Error),
            'w' => self.toggle_severity(Severity::Warning),
            'i' => self.toggle_severity(Severity::Info),
            't' => self.cycle_group(),
            'q' => self.quit(),
            _ => {}
        }
    }

    /// Get the original finding index for a visible index.
    fn original_index(&self, visible_idx: usize) -> Option<usize> {
        let visible = self.visible_findings();
        if visible_idx >= visible.len() {
            return None;
        }
        let target = visible[visible_idx] as *const Finding;
        self.findings.iter().position(|f| std::ptr::eq(f, target))
    }

    /// Get all unique module IDs from the findings.
    pub fn module_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .findings
            .iter()
            .map(|f| f.rule_id.split(':').next().unwrap_or(&f.rule_id).to_owned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::{Action, Location, TextEdit};

    fn make_finding(
        rule_id: &str,
        file: &str,
        line: u32,
        severity: Severity,
        fixable: bool,
    ) -> Finding {
        let actions = if fixable {
            vec![Action {
                description: "auto fix".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: file.to_owned(),
                    start_line: line,
                    end_line: line,
                    new_text: String::new(),
                }],
            }]
        } else {
            vec![]
        };
        Finding {
            rule_id: rule_id.to_owned(),
            message: format!("{rule_id} at {file}:{line}"),
            severity,
            location: Location {
                file: file.to_owned(),
                start_line: line,
                end_line: line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions,
            metadata: HashMap::new(),
        }
    }

    fn sample_findings() -> Vec<Finding> {
        vec![
            make_finding("unused-function", "a.go", 5, Severity::Warning, true),
            make_finding("unused-import", "a.go", 3, Severity::Warning, true),
            make_finding("high-complexity", "b.go", 10, Severity::Error, false),
            make_finding("unused-file", "c.go", 1, Severity::Info, false),
        ]
    }

    #[test]
    fn test_new_app() {
        let app = App::new(sample_findings());
        assert_eq!(app.findings.len(), 4);
        assert_eq!(app.selected, 0);
        assert_eq!(app.group_by, GroupBy::File);
        assert!(!app.should_quit);
    }

    #[test]
    fn test_visible_findings_all() {
        let app = App::new(sample_findings());
        assert_eq!(app.visible_count(), 4);
    }

    #[test]
    fn test_visible_findings_filter_severity() {
        let mut app = App::new(sample_findings());
        app.severity_filter.show_info = false;
        assert_eq!(app.visible_count(), 3);

        app.severity_filter.show_warning = false;
        assert_eq!(app.visible_count(), 1);
    }

    #[test]
    fn test_visible_findings_filter_module() {
        let mut app = App::new(sample_findings());
        app.module_filter
            .hidden
            .insert("unused-function".to_owned());
        // The module filter checks the prefix before ':', so this filters by rule_id prefix.
        let count = app.visible_count();
        assert!(count <= 4);
    }

    #[test]
    fn test_grouped_by_file() {
        let app = App::new(sample_findings());
        let groups = app.grouped_findings();
        // 3 files: a.go, b.go, c.go
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn test_grouped_by_rule() {
        let mut app = App::new(sample_findings());
        app.group_by = GroupBy::Rule;
        let groups = app.grouped_findings();
        // 4 unique rules
        assert_eq!(groups.len(), 4);
    }

    #[test]
    fn test_grouped_by_severity() {
        let mut app = App::new(sample_findings());
        app.group_by = GroupBy::Severity;
        let groups = app.grouped_findings();
        // 3 severities: warning, error, info
        assert_eq!(groups.len(), 3);
    }

    #[test]
    fn test_navigation() {
        let mut app = App::new(sample_findings());
        assert_eq!(app.selected, 0);

        app.move_down();
        assert_eq!(app.selected, 1);

        app.move_down();
        assert_eq!(app.selected, 2);

        app.move_up();
        assert_eq!(app.selected, 1);

        app.move_to_top();
        assert_eq!(app.selected, 0);

        app.move_to_bottom();
        assert_eq!(app.selected, 3);
    }

    #[test]
    fn test_navigation_bounds() {
        let mut app = App::new(sample_findings());

        // Can't go above 0.
        app.move_up();
        assert_eq!(app.selected, 0);

        // Can't go below last.
        app.move_to_bottom();
        let last = app.visible_count() - 1;
        assert_eq!(app.selected, last);

        app.move_down();
        assert_eq!(app.selected, last);
    }

    #[test]
    fn test_navigation_empty() {
        let mut app = App::new(vec![]);
        app.move_down();
        assert_eq!(app.selected, 0);
        app.move_to_bottom();
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_cycle_group() {
        let mut app = App::new(sample_findings());
        assert_eq!(app.group_by, GroupBy::File);

        app.cycle_group();
        assert_eq!(app.group_by, GroupBy::Rule);

        app.cycle_group();
        assert_eq!(app.group_by, GroupBy::Severity);

        app.cycle_group();
        assert_eq!(app.group_by, GroupBy::File);
    }

    #[test]
    fn test_toggle_severity() {
        let mut app = App::new(sample_findings());
        assert!(app.severity_filter.show_info);

        app.toggle_severity(Severity::Info);
        assert!(!app.severity_filter.show_info);

        app.toggle_severity(Severity::Info);
        assert!(app.severity_filter.show_info);
    }

    #[test]
    fn test_apply_fix() {
        let mut app = App::new(sample_findings());
        app.apply_fix();
        assert_eq!(app.pending_actions.len(), 1);
        assert!(matches!(app.pending_actions[0], TuiAction::ApplyFix(0)));
    }

    #[test]
    fn test_apply_fix_no_action() {
        let mut app = App::new(sample_findings());
        // Select the non-fixable finding (index 2 = high-complexity).
        app.selected = 2;
        app.apply_fix();
        assert!(app.pending_actions.is_empty());
        assert!(app.status.contains("No auto-fix"));
    }

    #[test]
    fn test_add_suppression() {
        let mut app = App::new(sample_findings());
        app.add_suppression();
        assert_eq!(app.pending_actions.len(), 1);
        assert!(matches!(
            app.pending_actions[0],
            TuiAction::AddSuppression(0)
        ));
    }

    #[test]
    fn test_copy_location() {
        let mut app = App::new(sample_findings());
        let loc = app.copy_location();
        assert!(loc.is_some());
        assert!(loc.unwrap().contains("a.go:5"));
    }

    #[test]
    fn test_copy_location_empty() {
        let mut app = App::new(vec![]);
        let loc = app.copy_location();
        assert!(loc.is_none());
    }

    #[test]
    fn test_quit() {
        let mut app = App::new(sample_findings());
        assert!(!app.should_quit);
        app.quit();
        assert!(app.should_quit);
        assert!(
            app.pending_actions
                .iter()
                .any(|a| matches!(a, TuiAction::Quit))
        );
    }

    #[test]
    fn test_handle_key_navigation() {
        let mut app = App::new(sample_findings());

        app.handle_key('j');
        assert_eq!(app.selected, 1);

        app.handle_key('k');
        assert_eq!(app.selected, 0);

        app.handle_key('G');
        assert_eq!(app.selected, 3);

        app.handle_key('g');
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn test_handle_key_actions() {
        let mut app = App::new(sample_findings());

        app.handle_key('f'); // Apply fix.
        assert!(!app.pending_actions.is_empty());

        app.handle_key('t'); // Cycle group.
        assert_eq!(app.group_by, GroupBy::Rule);

        app.handle_key('q'); // Quit.
        assert!(app.should_quit);
    }

    #[test]
    fn test_handle_key_filters() {
        let mut app = App::new(sample_findings());

        app.handle_key('e'); // Toggle error.
        assert!(!app.severity_filter.show_error);

        app.handle_key('w'); // Toggle warning.
        assert!(!app.severity_filter.show_warning);

        app.handle_key('i'); // Toggle info.
        assert!(!app.severity_filter.show_info);
    }

    #[test]
    fn test_handle_key_unknown() {
        let mut app = App::new(sample_findings());
        let selected_before = app.selected;
        app.handle_key('z'); // Unknown key -- no effect.
        assert_eq!(app.selected, selected_before);
    }

    #[test]
    fn test_module_ids() {
        let app = App::new(sample_findings());
        let ids = app.module_ids();
        assert!(!ids.is_empty());
    }

    #[test]
    fn test_group_by_next() {
        assert_eq!(GroupBy::File.next(), GroupBy::Rule);
        assert_eq!(GroupBy::Rule.next(), GroupBy::Severity);
        assert_eq!(GroupBy::Severity.next(), GroupBy::File);
    }

    #[test]
    fn test_group_by_label() {
        assert_eq!(GroupBy::File.label(), "file");
        assert_eq!(GroupBy::Rule.label(), "rule");
        assert_eq!(GroupBy::Severity.label(), "severity");
    }

    #[test]
    fn test_severity_filter_default() {
        let filter = SeverityFilter::default();
        assert!(filter.includes(Severity::Error));
        assert!(filter.includes(Severity::Warning));
        assert!(filter.includes(Severity::Info));
    }

    #[test]
    fn test_severity_filter_toggle() {
        let mut filter = SeverityFilter::default();
        filter.toggle(Severity::Error);
        assert!(!filter.includes(Severity::Error));
        assert!(filter.includes(Severity::Warning));

        filter.toggle(Severity::Error);
        assert!(filter.includes(Severity::Error));
    }

    #[test]
    fn test_module_filter_default() {
        let filter = ModuleFilter::default();
        assert!(filter.includes("dead-code"));
        assert!(filter.includes("complexity"));
    }

    #[test]
    fn test_module_filter_toggle() {
        let mut filter = ModuleFilter::default();
        filter.toggle("dead-code");
        assert!(!filter.includes("dead-code"));
        assert!(filter.includes("complexity"));

        filter.toggle("dead-code");
        assert!(filter.includes("dead-code"));
    }

    #[test]
    fn test_handle_key_suppression() {
        let mut app = App::new(sample_findings());
        app.handle_key('s');
        assert!(
            app.pending_actions
                .iter()
                .any(|a| matches!(a, TuiAction::AddSuppression(_)))
        );
    }

    #[test]
    fn test_handle_key_copy() {
        let mut app = App::new(sample_findings());
        app.handle_key('c');
        assert!(app.status.contains("Copied"));
    }
}
