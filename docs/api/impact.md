# Impact Tracking

Save analysis snapshots, compare trends over time, and measure fix/introduce rates.

## CLI usage

### Save a snapshot

```bash
chaffra impact --save-snapshot snapshots/v1.0.json --label v1.0 .
```

### Compare against a baseline

```bash
chaffra impact --baseline snapshots/v1.0.json --label v1.1 .
chaffra impact --baseline snapshots/v1.0.json --format json .
```

### View current state (no baseline)

```bash
chaffra impact .
```

## Output format

### Markdown table (default)

```
## Impact Report: v1.0 -> v1.1

| Metric | Baseline | Current | Delta | Trend |
|--------|----------|---------|-------|-------|
| total_findings | 10.0 | 5.0 | -5.0 | v (improving) |
| health_score | 70.0 | 85.0 | +15.0 | v (improving) |

### Catch Rate

- Fixed: 5
- Introduced: 0
- Persisted: 5
- Fix rate: 50.0%
```

### JSON

The `--format json` flag outputs a `TrendReport` JSON object with `trends` and
`catch_rate` fields.

## API

### `chaffra_impact::create_snapshot(result, health, label) -> Snapshot`

Creates a snapshot from analysis results and optional health data.

### `chaffra_impact::save_snapshot(snapshot, path) -> Result`

Serializes a snapshot to a JSON file.

### `chaffra_impact::load_snapshot(path) -> Result<Snapshot>`

Loads a snapshot from a JSON file.

### `chaffra_impact::compare_snapshots(baseline, current) -> TrendReport`

Compares two snapshots and produces a trend report with per-metric direction
and catch rate analysis.

## Types

- `Snapshot`: point-in-time capture of finding counts, health score, and metrics
- `TrendDirection`: `Improving | Stable | Regressing`
- `MetricTrend`: per-metric baseline, current, delta, and direction
- `CatchRate`: fixed, introduced, persisted counts, and fix rate percentage
- `TrendReport`: full comparison with trends and catch rate
