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
| `finding-churn` | Finding churn | info | telemetry | Reports new, resolved, and unchanged findings between runs |
| `sampling-status` | Sampling status | info | telemetry | Reports operator telemetry sampling configuration |

## Core Metrics (auto-collected)

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.analysis.duration_ms` | histogram | Total analysis duration |
| `chaffra.analysis.files_total` | counter | Total files analyzed |
| `chaffra.analysis.findings_total` | counter | Findings by severity and module |
| `chaffra.module.call_duration_ms` | histogram | Per-module call duration |
| `chaffra.module.error_total` | counter | Per-module error count |

## Finding Churn Metrics

Track deltas between analysis runs to measure codebase stability.

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.findings.new` | counter | Findings not in previous run |
| `chaffra.findings.resolved` | counter | Findings in previous run but not current |
| `chaffra.findings.unchanged` | counter | Findings present in both runs |
| `chaffra.findings.churn_rate` | gauge | Churn rate: new / (new + unchanged) |

State is persisted in `.chaffra-telemetry-state.json` for non-audit runs that don't have an explicit baseline.

## Error Metrics

Emitted when modules fail to load, configs are malformed, or plugins are unreachable.

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.module.load_error_total` | counter | Module load failures by module_id and error_type |
| `chaffra.config.parse_error_total` | counter | Config parse failures |
| `chaffra.plugin.connect_error_total` | counter | External module gRPC connection failures |

## Startup Timing Metrics

Per-module initialization time (relevant post-Phase 11 when all modules are gRPC servers).

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.module.startup_duration_ms` | histogram | Per-module initialization time |
| `chaffra.startup.total_duration_ms` | gauge | Total time from process start to all modules ready |

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

## Sampling

Configurable sampling rate for operator telemetry in high-volume environments.

```toml
[modules.telemetry]
sampling-rate = 1.0        # 1.0 = every run, 0.1 = 10% of runs, 0 = off
sampling-strategy = "rate"  # rate | on-change
```

| Strategy | Behavior |
|----------|----------|
| `rate` | Emit operator metrics on a random fraction of runs |
| `on-change` | Emit only when findings change compared to the previous run |

## Configuration

```toml
[modules.telemetry]
audience = "on"              # on | off | user-only | operator-only
backend = "json-file"        # json-file | stderr | prometheus | otlp | statsd | cloudwatch
endpoint = ""                # For OTLP/StatsD/CloudWatch
path = "chaffra-telemetry.json"  # For json-file backend
sampling-rate = 1.0          # 0.0–1.0
sampling-strategy = "rate"   # rate | on-change
```

## Parse Cache Metrics (helper API)

Library helper for tracking incremental parse cache effectiveness. Provides atomic counters and a `flush_to_collector()` method for integration into cache-aware code paths.

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.parse.cache_hits` | counter | Files served from parse cache |
| `chaffra.parse.cache_misses` | counter | Files re-parsed (cache miss) |
| `chaffra.parse.cache_hit_rate` | gauge | Hit rate: hits / (hits + misses) |
| `chaffra.parse.cache_size_bytes` | gauge | Current cache memory usage |
| `chaffra.parse.cache_evictions` | counter | Cache entries evicted |

Integration into the watch mode and LSP parse cache producers is planned for a future phase. Until then, these metrics are available as a library API for downstream consumers to call directly.

## Grafana Dashboard Generator

Generate an import-ready Grafana dashboard JSON for the full chaffra metric set.

```
chaffra telemetry dashboard                         # Write chaffra-grafana-dashboard.json
chaffra telemetry dashboard --datasource otlp       # OTLP datasource variant
chaffra telemetry dashboard --stdout                # Print to stdout
```

Panels: health score trend, finding count by module, finding churn, module call duration, findings by severity, error rates, startup time.

Row grouping: Overview (health + findings), Per-module detail, Operational (timing + errors).

Template variables: `tenant_id`, `environment`, `project`.

## Telemetry Audit Log (helper API)

Library helper for GDPR-style accountability logging. Provides event types, append/read functions, and display/export formatters for telemetry configuration change records.

Location: `.chaffra-telemetry-audit.log` (JSON lines format).

Event types: telemetry enabled/disabled, backend added/removed/modified, tenant-id changed, path-mode changed, sampling rate changed.

Integration into the actual configuration mutation paths (CLI config changes, MCP config updates) is planned for a future phase. Until then, the writer functions (`log_telemetry_enabled`, `log_backend_added`, etc.) are available as a library API. The CLI reader is available now:

```
chaffra telemetry audit-log            # Display the audit log
chaffra telemetry audit-log --export   # Export as JSON array for GDPR data subject access requests
```

## CLI

```
chaffra telemetry status      # Show backends and connection status
chaffra telemetry test        # Emit test metric, report success/failure
chaffra telemetry inspect     # Dry-run: show metric payload
chaffra telemetry dashboard   # Generate Grafana dashboard JSON
chaffra telemetry audit-log   # Display telemetry audit log

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
