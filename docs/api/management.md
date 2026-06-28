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
- Active telemetry backends and connection status (operator audience only; withheld under the default `user-only`)
- Active config: loaded modules, enabled rules, thresholds
- Auto-refreshes every 10 seconds

## REST API

### `GET /api/v1/metrics`

Current metric values.

This response is **audience-projected** (via the same `project_for_audience`
guard the CLI/MCP/backend-flush paths use). Under the default `user-only` the
`data_points` array contains only user-facing metrics (e.g. finding totals);
operator metrics such as `chaffra.module.call_duration_ms` and
`chaffra.module.error_total` are scrubbed. The `backends` array is operator-shaped
status metadata (backend kind / endpoint / connectivity) and is likewise withheld
— **empty** — under `user-only` (and under `off`). The management collector is
built from the CLI telemetry config, so a default `chaffra management` run
discloses no operator metrics or backend metadata.

```json
{
  "files_total": 42,
  "analysis_duration_ms": 1500,
  "data_points": [
    { "name": "chaffra.findings.new", "value": 3.0, "labels": {} }
  ],
  "backends": []
}
```

Under an operator-enabled audience (`on` / `operator-only`) operator data points
and the `backends` array are populated, e.g.:

```json
{
  "data_points": [
    { "name": "chaffra.module.call_duration_ms", "value": 150.0, "labels": { "module": "dead-code" } }
  ],
  "backends": [
    { "name": "json-file", "kind": "JsonFile", "connected": true, "message": "will write to chaffra-telemetry.json" }
  ]
}
```

### `GET /api/v1/metrics/history?window=7d`

**Status: not implemented.** Returns an explicit `not_implemented` status. Time-series history requires the streaming/watch mode integration (co-located mode). This endpoint will return populated snapshots once that integration is available.

```json
{
  "window": "7d",
  "snapshots": [],
  "status": "not_implemented",
  "message": "Time-series history requires the streaming/watch mode integration. This endpoint will return snapshots once co-located mode is available."
}
```

### `GET /api/v1/modules`

Registered modules, status, capabilities. Audience-projected. The module list is
built from the **user** summary, and `duration_ms` (the operator metric
`chaffra.module.call_duration_ms`) and `status` (derived from operator error
counts) are operator-shaped. The disclosure therefore depends on the resolved
audience:

- **`user-only`** (default): module rows are listed (finding counts are
  user-facing), but `duration_ms` is `0` and `status` is `healthy` — operator
  timing and error state are withheld; modules whose only contribution was
  operator timing are omitted entirely.
- **`on`**: full disclosure — real `duration_ms` and an `"error"` status when the
  module recorded errors.
- **`operator-only`**: this endpoint is sourced from the user summary, which the
  projection drops when the user scope is off, so the module list is **empty**.
  Operator-only opts out of user-scoped views; the raw operator metrics remain
  available via `GET /api/v1/metrics` `data_points`. (Driving `/modules` and
  `/health` from the operator summary under operator-only is deferred to Stage
  15a.3 alongside the co-located integration.)
- **`off`**: all telemetry is disabled — neither scope is enabled, so the
  projection drops the user summary entirely and the module list is **empty**
  (same as `operator-only` for this user-sourced endpoint).

`finding_count` is user-facing and reported whenever the user scope is on.

```json
{
  "modules": [
    { "id": "dead-code", "status": "healthy", "finding_count": 5, "duration_ms": 0, "capabilities": ["analyze", "explain"] }
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

Health score, grade, and per-file breakdown. Audience-projected. Health scores
come from the user-facing `chaffra.module.<id>.health_score` data points
(`KNOWN_USER`), so they are reported under `user-only` and `on`. Under
`operator-only` **and `off`** the user scope is off and these points are dropped,
so `score` is `null` and `grade` is `—` (same user-scoped-view caveat as
`/modules`; the operator-only case is revisited in Stage 15a.3, and `off` simply
disables all telemetry).

```json
{
  "score": 85.0,
  "grade": "B",
  "files": []
}
```

### `GET /api/v1/config`

Active configuration (redacted secrets).

The default audience is `UserOnly`. The `audience` and `sampling_strategy`
values are the `TelemetryAudience` / `SamplingStrategy` enum variant names
(the API serializes them with their Rust debug representation), distinct from
the kebab-case spelling accepted on input (`[modules.telemetry] audience =
"user-only"`, `--telemetry user-only`).

The `backends` array (backend kinds) is operator-shaped metadata: it is
populated only under an operator-enabled audience (`on` / `operator-only`) and
is **empty** under the default `user-only` (and under `off`), matching the
`GET /api/v1/metrics` backend gating.

```json
{
  "audience": "UserOnly",
  "sampling_rate": 1.0,
  "sampling_strategy": "Rate",
  "backends": []
}
```

Under an operator audience the `backends` array is populated (e.g.
`["JsonFile"]`).

## Lifecycle

- **Standalone mode** (`chaffra management`): starts an empty collector with core metric definitions registered. Useful for verifying the dashboard UI and API shape. Backend status (kind/connectivity) is operator-shaped and is shown only when started with an operator audience (`--telemetry on|operator-only`); a default (user-only) run returns an empty backends list. Does not contain analysis data.
- **Co-located mode** (watch/MCP/LSP): the management server shares the live `TelemetryCollector` used by analysis, exposing real-time metrics, findings, and churn data. All responses are audience-projected, as in standalone mode. Wiring into these modes is planned for a future phase (Stage 15a.3).
- Clean shutdown on Ctrl+C
- Binds to `127.0.0.1` only (localhost)

## Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9100` | Port for the management HTTP server |
