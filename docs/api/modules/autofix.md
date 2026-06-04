# Autofix Module

**Module ID:** `autofix`
**Crate:** `chaffra-autofix`
**Languages:** Go, Python

Orchestrates automated fix application across analysis modules. Collects fixable findings, detects edit conflicts, and applies safe text edits atomically per file.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `fix-applied` | Fix applied | info | An automated fix was successfully applied |
| `fix-conflict` | Fix conflict | warning | Overlapping edits detected; both skipped to avoid corruption |
| `fix-skipped` | Fix skipped | info | Finding has no auto-fixable action |

## Transaction Model

Fixes are applied atomically per file:

1. **Plan:** Collect all `TextEdit`s from fixable findings, grouped by file.
2. **Detect conflicts:** If two edits target overlapping line ranges in the same file, both are skipped.
3. **Apply:** Non-conflicting edits are applied in reverse line order (bottom-to-top) to preserve line numbers.
4. **Write:** Modified file contents are written back to disk.

If `--dry-run` is specified, step 4 is skipped and a preview is printed instead.

## Conflict Detection

Two edits conflict when:
- They target the same file, AND
- Their line ranges overlap: `edit_a.start_line <= edit_b.end_line && edit_b.start_line <= edit_a.end_line`

When a conflict is detected, **both** edits are skipped to avoid source corruption.

## Pre-commit Hooks

The module includes hook management:

- `chaffra hooks install` -- writes a `.git/hooks/pre-commit` shell script
- `chaffra hooks uninstall` -- removes the chaffra-managed hook
- The hook analyzes staged files only by running `chaffra dead-code` on each staged path before each commit

Hooks are identified by a marker comment (`# chaffra-managed-hook`). If an existing non-chaffra hook is present, the chaffra hook is appended rather than replacing it.

## CLI Usage

```bash
chaffra fix .                          # Apply all safe fixes
chaffra fix . --dry-run                # Preview fixes without applying
chaffra fix . --rule unused-import     # Fix only unused imports
chaffra hooks install                  # Install pre-commit hook
chaffra hooks uninstall                # Remove pre-commit hook
```

## API

### Key Functions

| Function | Description |
|----------|-------------|
| `collect_fixable(findings)` | Filter to findings with `auto_fixable = true` actions |
| `filter_by_rule(findings, rule_id)` | Filter findings by rule ID |
| `orchestrate_fixes(findings, dry_run)` | Plan, detect conflicts, apply edits |
| `apply_fixes_to_files(contents, results)` | Apply edits to file content strings |

### Key Types

| Type | Description |
|------|-------------|
| `PlannedEdit` | An edit tied to its originating finding index |
| `HookResult` | Enum: Installed, Uninstalled, AlreadyInstalled, NotInstalled |
