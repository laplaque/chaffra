# VS Code Extension (Planned)

Planned VS Code integration for chaffra codebase intelligence.

## Planned features

### Inline diagnostics

- Real-time dead code, complexity, and duplication warnings
- Severity-based underlines matching `.chaffra.toml` rule configuration
- Quick-fix actions for auto-fixable findings

### Health dashboard

- Project health score in the status bar
- Per-file health grades in the explorer
- Workspace health overview panel

### Impact tracking

- Snapshot comparison on branch switch
- Trend visualization in the sidebar
- Pre-commit catch rate summary

### Monorepo support

- Workspace member detection and scoping
- Per-workspace analysis filtering
- Changed-workspace highlighting

### Commands

- `chaffra: Run Health Check`
- `chaffra: Detect Dead Code`
- `chaffra: Show Impact Report`
- `chaffra: Detect Workspaces`
- `chaffra: Migrate Config`

### Configuration

Extension settings will mirror `.chaffra.toml` with VS Code-native overrides:

```json
{
  "chaffra.format": "terminal",
  "chaffra.healthScoreInStatusBar": true,
  "chaffra.runOnSave": true,
  "chaffra.groupByWorkspace": false
}
```

## Architecture

The extension will communicate with the chaffra CLI binary via:
1. Direct CLI invocation with `--format json` for batch operations
2. LSP protocol for real-time diagnostics (via `chaffra-mcp` crate)
3. MCP server for AI-assisted code review integration

## Status

This extension is in the planning phase. Core analysis, monorepo support,
impact tracking, and migration are implemented in the CLI and available now.
