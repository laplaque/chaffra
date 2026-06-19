# Management Interface

**Crate:** `chaffra-management`

Lightweight HTTP server with an embedded web dashboard and REST API for inspecting chaffra's runtime state.

## Quick Start

```bash
chaffra management                  # Start on default port 9100
chaffra management --port 8080      # Custom port
```

Dashboard: `http://localhost:9100/`
API base: `http://localhost:9100/api/v1/`

## Dashboard

Embedded web UI (HTML/JS served from the binary, no external dependencies):

- Current module status: registered, healthy, error
- Last run summary: health score, finding counts by category, duration
- Finding churn: new, resolved, unchanged since last run
- Active telemetry backends and connection status
- Active config: loaded modules, enabled rules, thresholds
- Auto-refreshes every 10 seconds

## REST API

### `GET /api/v1/metrics`

Current metric values.

```json
{
  "files_total": 42,
  "analysis_duration_ms": 1500,
  "data_points": [
    { "name": "chaffra.module.call_duration_ms", "value": 150.0, "labels": { "module": "dead-code" } }
  ],
  "backends": [
    { "name": "json-file", "kind": "JsonFile", "connected": true, "message": "will write to chaffra-telemetry.json" }
  ]
}
```

### `GET /api/v1/metrics/history?window=7d`

Time-series snapshot history. The response `status` indicates the data source:

- `seeded` — deterministic demo data (default standalone mode)
- `live` — real analysis data from `--path` mode or co-located analysis in the same process
- `empty` — no data available (`--telemetry off` mode)

Optional dimension filters (mutually exclusive, first match wins):

| Parameter | Example | Description |
|-----------|---------|-------------|
| `module` | `?module=dead-code` | Only snapshots containing data for this module |
| `severity` | `?severity=warning` | Only snapshots with findings at this severity |
| `metric` | `?metric=chaffra.module.call_duration_ms` | Only snapshots containing this metric (prefix match) |

```json
{
  "window": "7d",
  "snapshots": [ { "..." : "..." } ],
  "status": "seeded",
  "message": "Seeded demo/test data. Run an analysis to populate live metrics."
}
```

### `GET /api/v1/modules`

Registered modules, status, capabilities.

```json
{
  "modules": [
    { "id": "dead-code", "status": "healthy", "finding_count": 5, "duration_ms": 150, "capabilities": ["analyze", "explain"] }
  ]
}
```

### `GET /api/v1/findings/summary`

Aggregated finding counts by module and severity.

```json
{
  "total": 12,
  "by_module": { "dead-code": 5, "complexity": 7 },
  "by_severity": { "warning": 8, "info": 4 }
}
```

### `GET /api/v1/findings/churn`

New, resolved, and unchanged findings since last run.

```json
{
  "new_count": 3,
  "resolved_count": 1,
  "unchanged_count": 8,
  "churn_rate": 0.27
}
```

### `GET /api/v1/health`

Health score, grade, and per-file breakdown.

```json
{
  "score": 85.0,
  "grade": "B",
  "files": []
}
```

### `GET /api/v1/config`

Active configuration (redacted secrets).

```json
{
  "audience": "on",
  "sampling_rate": 1.0,
  "sampling_strategy": "rate",
  "backends": ["json-file"]
}
```

## Lifecycle

- **Default mode** (`chaffra management`): starts with deterministic seeded demo data. All data endpoints return pre-built snapshots for verifying the dashboard UI, API shape, and backend connectivity.
- **Live mode** (`chaffra management --path .`): runs analysis on the given directory and serves real telemetry data, including module results, finding counts, severity breakdowns, and churn.
- **Co-located mode**: when the management server runs in the same process as analysis (e.g. via library integration), it shares the `LiveTelemetryState` directly and reflects live results without any cross-process mechanism.
- **Off mode** (`chaffra --telemetry off management`): starts with empty state. All data endpoints return zero/empty defaults.
- Clean shutdown on Ctrl+C
- Binds to `127.0.0.1` only (localhost)

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9100` | Port for the management HTTP server |
