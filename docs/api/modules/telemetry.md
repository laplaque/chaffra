# Telemetry Module

**Module ID:** `telemetry`
**Crate:** `chaffra-telemetry`
**Languages:** (all -- language-agnostic)

Collects, aggregates, and sinks metrics and spans from all analysis modules. Supports user-facing summaries (included in output) and operator-level system metrics (sunk to backends).

## Rules

| Rule ID | Name | Default Severity | Category | Description |
|---------|------|-------------------|----------|-------------|
| `backend-status` | Backend status | info | telemetry | Reports telemetry backend connectivity status |
| `metric-summary` | Metric summary | info | telemetry | Summary of collected telemetry metrics from the current run |

## Core Metrics (auto-collected)

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.analysis.duration_ms` | histogram | Total analysis duration |
| `chaffra.analysis.files_total` | counter | Total files analyzed |
| `chaffra.analysis.findings_total` | counter | Findings by severity and module |
| `chaffra.module.call_duration_ms` | histogram | Per-module call duration |
| `chaffra.module.error_total` | counter | Per-module error count |

## Per-Category Summary Metrics

| Category | Metrics |
|----------|---------|
| dead-code | `unused_functions`, `unused_files` |
| complexity | `cyclomatic_avg`, `cognitive_avg`, `health_score` |
| duplication | `clone_count`, `duplicated_lines` |
| architecture | `violations`, `cycles` |
| security | `findings_by_severity`, `cve_count` |
| audit | `verdict`, `new_findings` |
| hotspot | `top_score` |

## Telemetry Audiences

| Audience | Scope | Default |
|----------|-------|---------|
| User-facing | Finding counts, durations, health scores in output | on |
| Operator | Call latencies, error rates, memory pressure to backends | on |

Control via `--telemetry on|off|user-only|operator-only`.

## Backends

### Local

| Backend | Format | Activation |
|---------|--------|------------|
| JSON file | `chaffra-telemetry.json` | default, every run |
| Stderr | JSON lines | `--telemetry-backend stderr` |
| Prometheus | `/metrics` exposition | watch/server mode only |

### Cloud (preview — payload generation only, no network export)

| Backend | Status | Activation |
|---------|--------|------------|
| OTLP | Preview: serializes OTLP payload, does not export | `--telemetry-backend otlp --telemetry-endpoint URL` |
| StatsD | UDP push | `--telemetry-backend statsd` |
| CloudWatch | Preview: generates PutMetricData payload, does not export | `cloudwatch` feature flag |

## Configuration

```toml
[modules.telemetry]
audience = "on"          # on | off | user-only | operator-only
backend = "json-file"    # json-file | stderr | prometheus | otlp | statsd | cloudwatch
endpoint = ""            # For OTLP/StatsD/CloudWatch
path = "chaffra-telemetry.json"  # For json-file backend
```

## CLI

```
chaffra telemetry status   # Show backends and connection status
chaffra telemetry test     # Emit test metric, report success/failure
chaffra telemetry inspect  # Dry-run: show metric payload

# Global flags on all commands:
--telemetry on|off|user-only|operator-only
--telemetry-backend json-file|stderr|otlp|statsd
--telemetry-endpoint http://localhost:4317
```

## MCP Tool

Tool name: `chaffra/telemetry`

Actions (returns default configuration, not live analysis state):
- `status` -- default backend configuration and availability
- `snapshot` -- preview metrics snapshot (core metrics registered but no analysis data)
- `backends` -- list of default backend definitions and their types

## gRPC Service

The `TelemetryCollector` gRPC service (defined in `module.proto`) accepts metric registrations, data points, and spans from modules:

```protobuf
service TelemetryCollector {
  rpc RegisterMetrics(RegisterMetricsRequest) returns (RegisterMetricsResponse);
  rpc RecordMetrics(RecordMetricsRequest) returns (RecordMetricsResponse);
  rpc RecordSpan(RecordSpanRequest) returns (RecordSpanResponse);
}
```
