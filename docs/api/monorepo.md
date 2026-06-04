# Monorepo Support

Workspace detection and per-workspace analysis scoping for polyglot monorepos.

## Supported workspace types

| Ecosystem | Manifest file | Detection |
|-----------|--------------|-----------|
| Go | `go.work` | `use` directives (block and single-line) |
| Rust | `Cargo.toml` | `[workspace] members` with glob expansion |
| JS/TS | `package.json` | `workspaces` array or `{packages: [...]}` object |
| JS/TS | `pnpm-workspace.yaml` | `packages:` list entries |
| Python | `pyproject.toml` | `[tool.chaffra.workspaces]` or `[tool.poetry.packages]` |
| Java | `settings.gradle[.kts]` | `include` directives |

## CLI usage

### Detect workspaces

```bash
chaffra workspaces .
chaffra workspaces --format json .
```

> **Note:** Per-workspace analysis filtering (`--changed-workspaces`) and grouped
> output (`--group-by workspace`) are not yet exposed through the CLI. Use the
> library API below for programmatic workspace scoping.

## API

### `chaffra_monorepo::detect_workspaces(root: &Path) -> Vec<Workspace>`

Scans the root directory for all supported workspace configurations and returns
one `Workspace` per detected manifest.

### `chaffra_monorepo::changed_workspaces(workspace: &Workspace, changed_files: &[String]) -> Vec<WorkspaceMember>`

Filters workspace members to only those containing at least one file from the
`changed_files` list (paths relative to the monorepo root).

## Types

- `WorkspaceKind`: enum of supported workspace manifest types
- `Workspace`: root path, kind, and member list
- `WorkspaceMember`: name and relative path of a workspace member
