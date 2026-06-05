# Audit Module

PR risk assessment: baselines, new-only vs all-issues gating, and pass/fail verdicts.

## Module ID

`audit`

## Rules

| Rule ID | Name | Default Severity | Description |
|---------|------|-----------------|-------------|
| `new-finding` | New finding | warning | A finding not present in the baseline |
| `score-regression` | Score regression | warning | Total finding count increased compared to baseline |
| `threshold-exceeded` | Threshold exceeded | error | Finding count exceeds the configured gate threshold |

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `gate-mode` | string | `new-only` | Gate mode: `new-only` or `all` |
| `warn-threshold` | integer | `1` | Number of relevant findings to trigger a warning |
| `fail-threshold` | integer | `5` | Number of relevant findings to trigger a failure |
| `baseline` | string | `.chaffra-baseline.json` | Path to the baseline file |

## Gate Modes

- **new-only**: Only findings not present in the baseline count toward thresholds. Existing tech debt does not block PRs.
- **all**: All current findings count toward thresholds regardless of baseline.

## Verdicts

- **pass**: Relevant finding count is below the warn threshold.
- **warn**: Relevant finding count meets or exceeds the warn threshold but is below the fail threshold.
- **fail**: Relevant finding count meets or exceeds the fail threshold.

## Baseline Management

Save a baseline:
```bash
chaffra dead-code . --format json > findings.json
# The audit module reads findings from JSON files
```

The baseline file (`.chaffra-baseline.json`) stores findings as JSON with a timestamp and finding identities (rule, file, line, message).

## Usage

```bash
# Run audit against baseline
chaffra audit .

# With custom thresholds
chaffra --config .chaffra.toml audit .
```

## Suppression

```go
// chaffra:ignore new-finding
// chaffra:ignore score-regression
// chaffra:ignore threshold-exceeded
```
