# Terminal UI

**Crate:** `chaffra-tui`
**Dependencies:** `ratatui`, `crossterm`

Interactive terminal interface for browsing, filtering, and acting on chaffra findings.

## Launch

```bash
chaffra tui .          # Analyze and open TUI
chaffra tui ./src      # Analyze a specific directory
```

## Layout

```
+---------------------------------------------------+
| chaffra | 42 of 56 findings | grouped by: file    |  <- header
+---------------------------------------------------+
| --- a.go (3 findings) ---                         |
| + [W] a.go:5 function `unused` is never used      |
| + [W] a.go:3 import `fmt` is never used           |
|   [I] a.go:1 file contains no used symbols        |
| --- b.go (1 finding) ---                          |  <- findings
| >> [E] b.go:10 cyclomatic complexity 25 > 20      |
+---------------------------------------------------+
| Fix queued for: unused-function                    |  <- status bar
+---------------------------------------------------+
| j/k: navigate | g/G: top/bottom | f: fix | ...    |  <- help bar
+---------------------------------------------------+
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `j` / Down | Move selection down |
| `k` / Up | Move selection up |
| `g` / Home | Jump to first finding |
| `G` / End | Jump to last finding |
| `f` | Apply fix for selected finding |
| `s` | Add suppression comment |
| `c` | Copy file:line location |
| `t` | Cycle grouping: file -> rule -> severity |
| `e` | Toggle error filter |
| `w` | Toggle warning filter |
| `i` | Toggle info filter |
| `q` / Esc | Quit |

## Grouping Modes

- **File:** Group findings by source file path
- **Rule:** Group findings by rule ID
- **Severity:** Group findings by severity level

## Filtering

Severity filters toggle visibility of findings at each level. When a filter is toggled off, findings at that severity are hidden from the list. Module filters can hide entire modules by ID.

## Fix Actions

When `f` is pressed on a finding with an auto-fixable action:

1. The fix is orchestrated through the autofix engine.
2. If no conflicts are detected, the edit is applied to disk.
3. The status bar updates to confirm the fix was applied.

Findings without auto-fixable actions show a status message explaining that no fix is available.
