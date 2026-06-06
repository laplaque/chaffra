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
- Finding trends over recent runs
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

Time-series over the specified window.

```json
{
  "window": "7d",
  "snapshots": []
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
  "audience": "On",
  "sampling_rate": 1.0,
  "sampling_strategy": "Rate",
  "backends": ["JsonFile"]
}
```

## Lifecycle

- Runs standalone via `chaffra management` for ad-hoc inspection
- Shares the tokio runtime when co-located with watch/MCP/LSP modes
- Clean shutdown on Ctrl+C
- Binds to `127.0.0.1` only (localhost)

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9100` | Port for the management HTTP server |
