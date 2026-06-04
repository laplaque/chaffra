# Hotspot Module

Churn x complexity ranking to surface files with the highest maintenance risk.

## Module ID

`hotspot`

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-----------------|-------------|
| `hotspot` | Hotspot | warning | File has a high churn x complexity score |
| `refactoring-target` | Refactoring target | error | File is in the top tier of hotspots and should be refactored |

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `hotspot-threshold` | float | `20.0` | Minimum hotspot score to flag as a hotspot |
| `refactoring-threshold` | float | `50.0` | Minimum hotspot score to flag as a refactoring target |
| `commit-counts` | JSON string | `{}` | JSON map of file paths to commit counts |
| `commits:<file>` | integer | - | Individual commit count for a specific file |

## Formula

```
hotspot_score = commit_count * avg_cyclomatic_complexity
```

- **commit_count**: Number of commits touching the file (from git log or config).
- **avg_cyclomatic_complexity**: Average cyclomatic complexity of functions in the file. Falls back to 1.0 for languages without tree-sitter support.

## Providing Commit Counts

Commit counts can be provided via configuration:

```toml
# .chaffra.toml
[modules.hotspot]
commit-counts = '{"main.go": 42, "utils.go": 15}'
```

Or via individual config entries:
```toml
[modules.hotspot]
"commits:main.go" = "42"
"commits:utils.go" = "15"
```

## Usage

```bash
# Run hotspot analysis
chaffra hotspot .

# With custom thresholds
chaffra --config .chaffra.toml hotspot .
```

## Suppression

```go
// chaffra:ignore hotspot
// chaffra:ignore refactoring-target
```
