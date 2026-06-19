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
| User-facing | Finding counts, durations, health scores in output | **user-only** (default) |
| Operator | Call latencies, error rates, memory pressure to backends | off (opt-in) |

Default changed from `on` to `user-only` in Phase 15a. Operator-level telemetry (backend sinks) requires explicit opt-in via `--telemetry on` or `--telemetry operator-only`. This aligns with GDPR data minimization: operators must consciously enable system-level metric collection.

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
audience = "user-only"       # on | off | user-only (default) | operator-only
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

Generate an import-ready Grafana dashboard JSON (Prometheus datasource) for the full chaffra metric set.

```
chaffra telemetry dashboard                         # Write chaffra-grafana-dashboard.json
chaffra telemetry dashboard --stdout                # Print to stdout
```

Panels: health score trend, finding count by module, finding churn, module call duration, findings by severity, error rates, startup time.

Row grouping: Overview (health + findings), Per-module detail, Operational (timing + errors).

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

Actions (reads from shared live telemetry state):
- `status` -- backend configuration and connectivity status
- `snapshot` -- latest live telemetry snapshot (redacted to user-scoped data unless operator audience is enabled)
- `backends` -- list of configured backend definitions and their types

MCP tool calls (`chaffra/health`, `chaffra/dead-code`) merge the target project's `[modules.telemetry]` config with the server-level config, compute finding churn, push snapshots to live state, and flush to configured backends.

## gRPC Service

The `TelemetryCollector` gRPC service (defined in `module.proto`) accepts metric registrations, data points, and spans from modules:

```protobuf
service TelemetryCollector {
  rpc RegisterMetrics(RegisterMetricsRequest) returns (RegisterMetricsResponse);
  rpc RecordMetrics(RecordMetricsRequest) returns (RecordMetricsResponse);
  rpc RecordSpan(RecordSpanRequest) returns (RecordSpanResponse);
}
```

## Live Telemetry State (Phase 15a)

Thread-safe shared telemetry state store (`LiveTelemetryState`) that maintains:

- The latest `TelemetrySnapshot`
- A bounded circular history buffer (max 1000 snapshots, `VecDeque`)
- State source tracking: `Live`, `Seeded`, or `Empty`

### State Sources

| Source | Meaning |
|--------|---------|
| `Live` | Populated from real analysis runs |
| `Seeded` | Populated with deterministic demo/test data |
| `Empty` | No data has been pushed yet |

### Querying History

Queryable by time window:

| Window | Duration |
|--------|----------|
| `1h` | 3,600,000 ms |
| `24h` | 86,400,000 ms |
| `7d` | 604,800,000 ms |

Queryable by dimension:

| Method | Filter |
|--------|--------|
| `history_by_module(module, window)` | Snapshots containing data for a specific module |
| `history_by_severity(severity, window)` | Snapshots with findings at a specific severity (non-zero count) |
| `history_by_metric(metric, window)` | Snapshots containing a specific metric (prefix match) |

The management API exposes these as query params on `GET /api/v1/metrics/history`: `?module=dead-code`, `?severity=warning`, `?metric=chaffra.module.call_duration_ms`. First matching filter wins; omit all for unfiltered results.

### Seeded / Demo Mode

`seed::seed_live_state()` returns a `LiveTelemetryState` pre-loaded with 12 deterministic snapshots:

- 3 modules (dead-code=92, complexity=78, security=65 health scores)
- Findings across error, warning, info severities
- Finding churn (new, resolved, unchanged)
- One intentionally slow module (security=850ms)
- Module errors and backend connectivity warnings
- Cache hit/miss metrics
- Snapshots spaced 15 hours apart over a simulated 7-day window
- Deterministic timestamps (base: `1_718_000_000_000`)

The `management` command behavior depends on the mode:

- **Default** (no `--path`): starts with seeded demo data for dashboard verification.
- **Live** (`--path .`): runs analysis on the given directory and serves real telemetry data through all API endpoints.
- **Off** (`--telemetry off`): starts with an empty state; all data endpoints return zero/empty defaults.

All data endpoints (`/metrics`, `/modules`, `/findings/*`, `/health`) read from the same `LiveTelemetryState`, ensuring consistency between current values and history.

### Management API

All data endpoints read from `LiveTelemetryState.current()` for current values and `history_window()` for historical data. The `/api/v1/metrics/history` endpoint includes a `status` field indicating the data source:

```
GET /api/v1/metrics/history?window=7d
```

Response includes a `status` field indicating the data source:

| Status | Meaning |
|--------|---------|
| `"live"` | Real analysis data |
| `"seeded"` | Deterministic demo data |
| `"empty"` | No data available |

Empty state response:
```json
{
  "status": "empty",
  "message": "No telemetry data available...",
  "window": "7d",
  "snapshots": []
}
```
