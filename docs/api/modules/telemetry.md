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
| User-facing | Finding counts, durations, health scores in output | **on** |
| Operator | Call latencies, error rates, startup/connection failures to backends | **off** |

The default audience is `user-only`: a default invocation collects user-facing
summary metrics only and **cannot** emit operator metrics. Operator telemetry
is opt-in.

### Audience modes

| Mode | User-facing | Operator | Projection at emission boundaries |
|------|-------------|----------|-----------------------------------|
| `on` | yes | yes | snapshot kept whole |
| `user-only` (default) | yes | no | `operator_summary`, every operator-only data point, every operator-only **definition**, and **all spans** are stripped before any flush/persistence |
| `operator-only` | no | yes | `user_summary` and every user-only data point/definition are stripped; operator data, definitions, and spans are kept |
| `off` | no | no | telemetry is disabled; nothing is collected or emitted |

Enable operator telemetry explicitly via either:

- the CLI flag: `--telemetry on` or `--telemetry operator-only`; or
- the file setting: `[modules.telemetry] audience = "on" | "operator-only"`.

Precedence (fail-closed): an explicit `--telemetry` flag is authoritative — it
overrides the file `audience`, which in turn overrides the `user-only` default.
A checked-in `[modules.telemetry] audience` can NOT re-enable operator emission
that the operator disabled on the command line (`--telemetry off`), nor widen a
narrower explicit `--telemetry user-only`. An unrecognised audience value (CLI
or file) is rejected with an actionable error — it is never coerced to a default
that would widen emission.

Scope classification has two inputs: the metric NAME and the data point's
PROVENANCE.

Name classification is driven by `chaffra_telemetry::metrics::metric_names`;
producers and the projector share those constants so naming cannot drift:

- **Operator-only data points and definitions**, matched by EXACT metric name
  (not prefix, so a per-module summary `chaffra.module.<id>.<key>` cannot
  collide with an operator name): `chaffra.module.call_duration_ms`,
  `chaffra.module.error_total`, `chaffra.module.startup_duration_ms`,
  `chaffra.module.load_error_total`, `chaffra.startup.total_duration_ms`,
  `chaffra.plugin.connect_error_total`, `chaffra.config.parse_error_total`, and
  the parse-cache family `chaffra.parse.cache_hits` / `cache_misses` /
  `cache_hit_rate` / `cache_size_bytes` / `cache_evictions`. Operator metric
  *definitions* are stripped under `user-only` too — the catalogue itself
  discloses which operator metrics exist.
- **User-facing data points**, matched by exact membership in `KNOWN_USER`
  (`chaffra.analysis.*`, `chaffra.findings.*`) OR the per-module summary shape
  `chaffra.module.<id>.<key>` emitted by the in-process
  `record_module_summary_metric` (health scores, clone counts).
- **Unclassified names** are admitted only under `on` (both scopes) and fail
  closed under `user-only` and `operator-only`.
- **Spans** are module execution traces (timing/correlation) and are
  operator-scoped in full: they are stripped under `user-only` and retained
  only when the operator scope is enabled.

Provenance overrides name. Built-in modules run in-process and record metrics
through trusted collector methods, so their names are classified as above.
External modules submit telemetry over gRPC and EVERY ingress routes through
a provenance-tracking entry point: data points via `record_untrusted_data_points`
(R3-3), definitions via `register_untrusted_metrics` (R4-2), and spans via
`record_untrusted_spans` (R5-1). Each writes the submitted name into the
snapshot's `untrusted_runtime` set (an internal, never-serialized field —
`#[serde(skip)]`). The projection forces any data point, definition, or span
whose name is in that set to the unclassified branch REGARDLESS of how the
name classifies, so an external plugin cannot cross `user-only` or
`operator-only` by spoofing a trusted user-facing or operator name — whether
a `chaffra.module.*` shape, an exact `KNOWN_USER` name like
`chaffra.analysis.findings_total`, or a span name a per-span scoping change
(issue #45) might make user-facing. This name-level provenance is the bounded
mitigation pending the same #45 — an `audience` field on `MetricDefinition`
derived server-side from a trusted `(module_id, name)` registry at gRPC
ingestion. The same provenance gate is applied when building the user-facing
`user_summary.module_summaries[*].metrics` map (R3-1), so a spoofed
`chaffra.module.<id>.<key>` cannot leak through that derived field either.

Projection is enforced at the TYPE LEVEL (R5-Structural). The
`TelemetrySnapshot::project_for_audience(self, audience) -> ProjectedSnapshot`
method is the ONLY constructor of `ProjectedSnapshot`; the
`TelemetryBackend::flush` and `TelemetryBackend::inspect` trait methods accept
`&ProjectedSnapshot`, and the MCP `chaffra/telemetry snapshot` boundary
projects before serialising. An output path that forgets to project is now a
COMPILE ERROR — every prior review round (R3 / R4 / R5) had found a parallel
"forgot to project at site X" leak; the newtype ends that class of bug.
Production callers continue to use the same rule they always have: **flush
the projected snapshot whenever the audience is not `off`**. Under `user-only`
a backend receives exactly the user-facing fields and never operator data;
under `off`, nothing crosses the emission boundary.

Audience-gated output beyond the snapshot itself (R4):

- `TelemetryModule::analyze` emits a `backend-status` finding (backend kind,
  endpoint/path, connectivity state). That is operator-shaped, so it surfaces
  ONLY when the resolved audience includes the operator scope (`On` /
  `OperatorOnly`); withheld under `user-only` and `off`.
- The MCP `chaffra/telemetry` tool's `status` and `backends` actions (backend
  connectivity / catalogue) follow the same gate. The `snapshot` action
  projects via `project_for_audience(config.audience)` before serializing.
- The CLI diagnostic commands `chaffra telemetry status` / `test` / `inspect`
  follow the same gate. Backend kind / endpoint / connectivity is operator-shaped
  *config metadata* — and `ProjectedSnapshot` scrubs the metric payload, not that
  metadata — so all three withhold backend information under `user-only` / `off`
  and disclose it only under `On` / `OperatorOnly` (R7-F3, R8-F1):
  - `status` prints the resolved audience; the backend catalogue/connectivity is
    withheld with a hint at the opt-in.
  - `test` exercises and names backends only under an operator audience; under
    `user-only` / `off` it withholds entirely (no backend is constructed,
    contacted, or named — this also subsumes the `Off` no-op).
  - `inspect` previews the per-backend payload only under an operator audience;
    otherwise the backend names and per-backend output are withheld.
- The MCP tool ALWAYS runs at the project's **resolved** audience: it loads the
  `path` repository root's `.chaffra.toml` through the same strict loader as the
  other tools and honours a `[modules.telemetry] audience` opt-in, falling back
  to the `user-only` default when the section is absent (R4-F1). A malformed
  config, an invalid `audience`, or an unresolvable `path` fails closed with a
  typed error. There is no caller-supplied `audience` override — the audience is
  never read from request params (R5-2). To preview other audiences, use the
  CLI's `chaffra telemetry inspect --telemetry <audience>` diagnostic, the
  trusted operator-side entry point.
- The **management HTTP server** (`chaffra management`, see
  [`management.md`](management.md)) is an output boundary too: every handler that
  reads the collector snapshot projects it via
  `project_for_audience(config.audience)` before serializing, so under the default
  `user-only` it discloses no operator data points or per-module timing/error
  state. Backend kind/connectivity **and the sampling configuration**
  (`sampling_rate` / `sampling_strategy`) are operator-shaped *config metadata*
  (not part of the snapshot) and carry their own `operator_enabled()` gate: the
  `/metrics` and `/config` backend lists are empty and the `/config` sampling
  fields are `null` under `user-only` / `off` (R10-F2, R13). `chaffra management`
  also resolves its telemetry config through the same shared fail-closed loader as
  the live runs (R11-F1), so a checked-in `[modules.telemetry]` audience/backend
  governs it. The co-located live-collector / history integration is deferred
  (Stage 15a.3); the audience gate on the standalone outputs is enforced now.

#### GDPR rationale

Operator metrics describe process- and environment-shaped behaviour (per-module
latencies, error/connection failures, startup timing) that can be combined with
deployment context to characterise an individual operator or environment. Under
GDPR data-minimisation (Art. 5(1)(c)) such operational metadata should not be
collected or forwarded unless explicitly justified. Defaulting to `user-only`
makes operator emission an explicit, auditable opt-in rather than implicit
behaviour.

Every live `run_with_telemetry` invocation that is OPTED IN to telemetry
appends one accountability event to `.chaffra-telemetry-audit.log`: a
`TelemetryEnabled` event recording the resolved audience (and best-effort
process-owner attribution) when operator telemetry is active (`on` /
`operator-only`), and a `TelemetryDisabled` event under `user-only` (the
user-facing surface emits, the operator scope is off).

Under `--telemetry off` the audit log is NOT written (R5-Audit-Off). `off` is
the operator's explicit "do not emit, write, or leave traces" instruction;
honouring the kill switch means even the accountability trail stays silent.
Accountability is preserved for every *opted-in* audience.

The diagnostic previews (`telemetry status` / `test` / `inspect`) deliberately
do not write to the audit log either — they never ran a workload, so there is
nothing to record. Inspect or export the log with `chaffra telemetry
audit-log [--export]`.

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

All values **fail closed**: a present-but-unrecognised `audience`, `backend`,
or `sampling-strategy`, or a non-numeric / non-finite (`NaN`/`inf`)
`sampling-rate`, is surfaced as a typed configuration error rather than coerced
to a default. (A finite but out-of-range `sampling-rate` is clamped to
`[0.0, 1.0]`.) The same typed parsers back the CLI flags — `--telemetry`,
`--telemetry-backend` — so an invalid flag value errors identically.

## Parse Cache Metrics (helper API)

Library helper for tracking incremental parse cache effectiveness. Provides atomic counters and a `flush_to_collector()` method for integration into cache-aware code paths.

| Metric | Kind | Description |
|--------|------|-------------|
| `chaffra.parse.cache_hits` | counter | Files served from parse cache |
| `chaffra.parse.cache_misses` | counter | Files re-parsed (cache miss) |
| `chaffra.parse.cache_hit_rate` | gauge | Hit rate: hits / (hits + misses) |
| `chaffra.parse.cache_size_bytes` | gauge | Current cache memory usage |
| `chaffra.parse.cache_evictions` | counter | Cache entries evicted |

All five parse-cache metrics are **operator-scoped** (memory/eviction pressure):
they are classified as operator-only and withheld under `user-only`, the same as
the other operator metrics above.

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
chaffra telemetry status      # Show resolved audience; backend catalogue/connectivity shown ONLY under on|operator-only (withheld under user-only/off)
chaffra telemetry test        # Emit test metric; exercises/names backends only under on|operator-only (withheld under user-only/off)
chaffra telemetry inspect     # Dry-run payload preview; backend names/output shown only under on|operator-only (withheld under user-only/off)
chaffra telemetry dashboard   # Generate Grafana dashboard JSON
chaffra telemetry audit-log   # Display telemetry audit log

# Global flags on all commands:
--telemetry on|off|user-only|operator-only   # default: user-only (operator metrics off)
--telemetry-backend json-file|stderr|otlp|statsd
--telemetry-endpoint http://localhost:4317
```

## Migration notes (Phase 15a.1)

- **Default audience changed from `on` to `user-only`.** Runs that previously
  emitted operator metrics (call latencies, error/startup/connection counters)
  to backends by default now emit only user-facing summary metrics. No flag or
  config was required before; operator emission now requires an explicit opt-in.
- **To restore the prior behaviour**, pass `--telemetry on` or set
  `[modules.telemetry] audience = "on"`. To collect operator metrics only, use
  `--telemetry operator-only` / `audience = "operator-only"`.
- **Invalid audience values now fail closed.** A typo in `--telemetry` or in
  `[modules.telemetry] audience` is now a hard error instead of silently
  falling back to a default. Fix the value to proceed.
- **An explicit `--telemetry` flag now wins over the file `audience`.** Earlier
  builds let a checked-in `[modules.telemetry] audience` override the command
  line; it no longer can. In particular `--telemetry off` (or `user-only`) on
  the command line can no longer be re-enabled or widened by a committed config.
- **A file `[modules.telemetry] backend` now takes effect on live CLI runs.**
  Earlier builds applied the file's `audience`/sampling but dropped its
  `backend`, so a checked-in `backend = "stderr"` was silently ignored on a live
  CLI run (the default JSON-file sink was used instead). The file backend is now
  honoured when no `--telemetry-backend` / `--telemetry-endpoint` is given; an
  explicit CLI backend selector still wins (precedence: CLI backend > file
  `backend` > default).
- **Audience aliases tightened.** `audience` accepts only `on` / `off` /
  `user-only` / `operator-only` (plus the snake_case `user_only` /
  `operator_only`). The previously-accepted bare `user` / `operator` and the
  `true` / `1` / `false` / `0` spellings now fail closed.
- **Spans and operator metric definitions are now stripped under `user-only`.**
  Module trace/timing spans are operator-scoped, and the operator metric
  *definition* catalogue is withheld too, so a `user-only` payload no longer
  discloses operator traces or which operator metrics exist. The parse-cache
  metrics (`chaffra.parse.cache_*`) are now classified operator-only as well.
- No on-disk format, metric names, backend payloads, or gRPC schema changed.
  Existing dashboards and backends continue to work once operator telemetry is
  re-enabled.

## MCP Tool

Tool name: `chaffra/telemetry`

The tool resolves the project's telemetry config strictly from the `path`
repository root's `.chaffra.toml` (the optional `path` param defaults to the
current directory) — the same strict loader the other MCP tools and the CLI
use. A `[modules.telemetry] audience` opt-in is honoured; absent that, the
audience is the `user-only` default. Operator-shaped output (`status` /
`backends`) is withheld under `user-only` and surfaces only when the project
file opts in with `audience = "on"` / `"operator-only"`. There is no request
parameter that can widen the audience, and a malformed config or invalid
`audience` fails closed with an error.

Actions (project-resolved configuration, not live analysis state):
- `status` -- configured backend availability at the resolved audience (`[]` under `user-only`)
- `snapshot` -- audience-projected metrics snapshot (core metrics registered but no analysis data)
- `backends` -- configured backend definitions and their types at the resolved audience (`[]` under `user-only`)

## gRPC Service

The `TelemetryCollector` gRPC service (defined in `module.proto`) accepts metric registrations, data points, and spans from modules:

```protobuf
service TelemetryCollector {
  rpc RegisterMetrics(RegisterMetricsRequest) returns (RegisterMetricsResponse);
  rpc RecordMetrics(RecordMetricsRequest) returns (RecordMetricsResponse);
  rpc RecordSpan(RecordSpanRequest) returns (RecordSpanResponse);
}
```
