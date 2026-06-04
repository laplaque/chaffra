# Complexity Module

**Module ID:** `complexity`
**Crate:** `chaffra-complexity`
**Languages:** Go, Python

Computes cyclomatic and cognitive complexity per function, derives per-file and per-project health scores, and reports functions exceeding configured thresholds.

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-------------------|-------------|
| `high-cyclomatic` | High cyclomatic complexity | warning | Function exceeds cyclomatic complexity threshold |
| `high-cognitive` | High cognitive complexity | warning | Function exceeds cognitive complexity threshold |
| `low-health-score` | Low health score | warning | File health score is below configured threshold |

## Metrics

### Cyclomatic Complexity

Counts independent control-flow paths through a function. Starts at 1 (the base path) and increments for each:

- `if` / `else if` / `elif`
- `for` / `while`
- `switch` / `case` / `except`
- `&&` / `||` boolean operators

### Cognitive Complexity

Weights nesting depth to better reflect human comprehension cost:

- Each control structure adds 1 + current nesting depth
- Boolean operators add 1 (no nesting penalty)
- `elif` adds 1 (no nesting penalty, since it is at the same level as `if`)

### Health Score

Per-file composite score from 0-100:

```
score = 100 - (cyclomatic_penalty + cognitive_penalty + size_penalty + nesting_penalty)
```

Clamped to [0, 100].

| Penalty | Formula |
|---------|---------|
| Cyclomatic | `min(30, (avg_cyclomatic - threshold) * 3)` if over threshold |
| Cognitive | `min(30, (avg_cognitive - threshold) * 3)` if over threshold |
| Size | `min(20, (max_lines - 100) / 20)` if any function > 100 lines |
| Nesting | `min(20, (max_nesting - 4) * 5)` if any function nesting > 4 |

### Project Health

Weighted average of all file scores.

### Letter Grades

| Grade | Score Range |
|-------|------------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | < 60 |

## Configuration

In `.chaffra.toml`:

```toml
[health]
max-cyclomatic = 20
max-cognitive = 15
min-score = 70
```

Or per-module:

```toml
[modules.complexity]
max-cyclomatic = "15"
max-cognitive = "10"
min-score = "80"
```

## CLI Usage

```bash
chaffra health .                       # Show health scores
chaffra health ./src --format json     # JSON output
chaffra explain complexity:high-cyclomatic  # Explain a rule
```
