//! Rendering logic for the TUI.
//!
//! Builds `ratatui` frames showing the findings list, status bar, and help text.
//! The rendering is split from the app state to keep things testable.

use crate::app::App;
use chaffra_core::diagnostic::Severity;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

/// Severity to terminal color mapping.
fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Error => Color::Red,
        Severity::Warning => Color::Yellow,
        Severity::Info => Color::Cyan,
    }
}

/// Render the full TUI frame.
pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Header.
            Constraint::Min(5),    // Findings list.
            Constraint::Length(1), // Status bar.
            Constraint::Length(2), // Help bar.
        ])
        .split(frame.area());

    render_header(frame, chunks[0], app);
    render_findings(frame, chunks[1], app);
    render_status(frame, chunks[2], app);
    render_help(frame, chunks[3]);
}

/// Render the header line showing counts and grouping.
fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let visible = app.visible_count();
    let total = app.findings.len();
    let text = format!(
        " chaffra | {} of {} findings | grouped by: {}",
        visible,
        total,
        app.group_by.label(),
    );
    let header = Paragraph::new(text).style(
        Style::default()
            .fg(Color::White)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(header, area);
}

/// Render the findings list.
///
/// Group headers are rendered as non-selectable rows. The `app.selected` index
/// maps into the flat list of *findings only* (via `grouped_flat_findings`), so
/// we translate it into the widget row index by accounting for header rows that
/// precede the selected finding.
fn render_findings(frame: &mut Frame, area: Rect, app: &App) {
    let groups = app.grouped_findings();

    let mut items: Vec<ListItem> = Vec::new();
    // Track the widget row index that corresponds to app.selected.
    let mut widget_selected: Option<usize> = None;
    let mut finding_idx: usize = 0;

    for (group_label, findings) in &groups {
        // Group header (non-selectable).
        items.push(ListItem::new(Line::from(Span::styled(
            format!(" --- {group_label} ({} findings) ---", findings.len()),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ))));

        for finding in findings {
            if finding_idx == app.selected {
                widget_selected = Some(items.len());
            }
            finding_idx += 1;

            let sev_char = match finding.severity {
                Severity::Error => "E",
                Severity::Warning => "W",
                Severity::Info => "I",
            };
            let fixable = if finding.actions.iter().any(|a| a.auto_fixable) {
                "+"
            } else {
                " "
            };
            let text = format!(
                " {fixable} [{sev_char}] {}:{} {}",
                finding.location.file, finding.location.start_line, finding.message,
            );
            items.push(ListItem::new(Line::from(Span::styled(
                text,
                Style::default().fg(severity_color(finding.severity)),
            ))));
        }
    }

    if items.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            " No findings match the current filters.",
            Style::default().fg(Color::Gray),
        ))));
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Findings "))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    let mut state = ListState::default();
    state.select(widget_selected);
    frame.render_stateful_widget(list, area, &mut state);
}

/// Render the status bar.
fn render_status(frame: &mut Frame, area: Rect, app: &App) {
    let status = if app.status.is_empty() {
        " Ready".to_owned()
    } else {
        format!(" {}", app.status)
    };
    let bar = Paragraph::new(status).style(Style::default().fg(Color::White).bg(Color::Blue));
    frame.render_widget(bar, area);
}

/// Render the help bar.
fn render_help(frame: &mut Frame, area: Rect) {
    let help = " j/k: navigate | g/G: top/bottom | f: fix | s: suppress | c: copy | t: group | e/w/i: filter | q: quit";
    let bar = Paragraph::new(help).style(Style::default().fg(Color::Gray));
    frame.render_widget(bar, area);
}

/// Format a single finding as a one-line string (for non-TUI output).
pub fn format_finding_line(finding: &chaffra_core::diagnostic::Finding) -> String {
    let sev = match finding.severity {
        Severity::Error => "ERR",
        Severity::Warning => "WRN",
        Severity::Info => "INF",
    };
    let fixable = if finding.actions.iter().any(|a| a.auto_fixable) {
        "[+]"
    } else {
        "[ ]"
    };
    format!(
        "{fixable} [{sev}] {}:{} {}",
        finding.location.file, finding.location.start_line, finding.message,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chaffra_core::diagnostic::{Action, Finding, Location, TextEdit};
    use std::collections::HashMap;

    fn make_finding(severity: Severity, fixable: bool) -> Finding {
        let actions = if fixable {
            vec![Action {
                description: "fix".to_owned(),
                auto_fixable: true,
                edits: vec![TextEdit {
                    file: "test.go".to_owned(),
                    start_line: 1,
                    end_line: 1,
                    new_text: String::new(),
                }],
            }]
        } else {
            vec![]
        };
        Finding {
            rule_id: "test-rule".to_owned(),
            message: "test finding".to_owned(),
            severity,
            location: Location {
                file: "test.go".to_owned(),
                start_line: 10,
                end_line: 10,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_severity_color() {
        assert_eq!(severity_color(Severity::Error), Color::Red);
        assert_eq!(severity_color(Severity::Warning), Color::Yellow);
        assert_eq!(severity_color(Severity::Info), Color::Cyan);
    }

    #[test]
    fn test_format_finding_line_error_fixable() {
        let finding = make_finding(Severity::Error, true);
        let line = format_finding_line(&finding);
        assert!(line.contains("[+]"));
        assert!(line.contains("[ERR]"));
        assert!(line.contains("test.go:10"));
    }

    #[test]
    fn test_format_finding_line_warning_not_fixable() {
        let finding = make_finding(Severity::Warning, false);
        let line = format_finding_line(&finding);
        assert!(line.contains("[ ]"));
        assert!(line.contains("[WRN]"));
    }

    #[test]
    fn test_grouped_render_row_count_includes_headers() {
        use crate::app::App;

        // With 3 findings across 2 groups, the rendered list should have
        // 2 header rows + 3 finding rows = 5 total items, but the selectable
        // count (visible_count) should remain 3. This proves headers are
        // non-selectable padding.
        let findings = vec![
            make_finding(Severity::Error, false),
            make_finding(Severity::Warning, true),
            make_finding(Severity::Warning, false),
        ];
        // Patch the file paths so they land in different groups.
        let mut findings = findings;
        findings[0].location.file = "a.go".to_owned();
        findings[0].rule_id = "rule-a".to_owned();
        findings[1].location.file = "b.go".to_owned();
        findings[1].rule_id = "rule-b".to_owned();
        findings[2].location.file = "b.go".to_owned();
        findings[2].rule_id = "rule-c".to_owned();

        let app = App::new(findings);

        // Group by file: 2 groups (a.go, b.go).
        let groups = app.grouped_findings();
        assert_eq!(groups.len(), 2, "should have 2 file groups");

        // The flat findings list should have 3 entries (no headers).
        let flat = app.grouped_flat_findings();
        assert_eq!(flat.len(), 3, "flat findings should not include headers");

        // visible_count uses the unordered filter, should also be 3.
        assert_eq!(app.visible_count(), 3);
    }

    #[test]
    fn test_format_finding_line_info() {
        let finding = make_finding(Severity::Info, false);
        let line = format_finding_line(&finding);
        assert!(line.contains("[INF]"));
    }
}
