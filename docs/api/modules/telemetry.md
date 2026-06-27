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
- The MCP tool ALWAYS runs at the project's **resolved** audience: it loads the
  `path` repository root's `.chaffra.toml` through the same strict loader as the
  other tools and honours a `[modules.telemetry] audience` opt-in, falling back
  to the `user-only` default when the section is absent (R4-F1). A malformed
  config, an invalid `audience`, or an unresolvable `path` fails closed with a
  typed error. There is no caller-supplied `audience` override — the audience is
  never read from request params (R5-2). To preview other audiences, use the
  CLI's `chaffra telemetry inspect --telemetry <audience>` diagnostic, the
  trusted operator-side entry point.

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
chaffra telemetry status      # Show backends and connection status
chaffra telemetry test        # Emit test metric, report success/failure
chaffra telemetry inspect     # Dry-run: show metric payload
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
