//! Telemetry collector: aggregates metrics and spans from all modules.

use crate::config::{TelemetryAudience, TelemetryConfig};
use crate::error::Result;
use crate::metrics::metric_names;
use crate::metrics::{MetricDataPoint, MetricDefinition, MetricKind, SpanData};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Whether a span is operator-scoped. Spans are module execution traces
/// (timing/correlation) — operator-level telemetry by nature — so today EVERY
/// span is operator-scoped and withheld from any audience without the operator
/// scope, exactly like the operator data points.
///
/// This is intentionally a per-span predicate rather than a blanket
/// "drop all spans" branch: the intent is that spans become individually
/// classifiable once they carry a scope tag. That source-tagging is deferred
/// alongside the metric source-tagging (proto-wire change, out of Stage 15a.1
/// scope); until then the constant-`true` body keeps the current
/// all-spans-operator behaviour while leaving the classification seam in place.
// TODO(#45): classify spans individually once SpanData carries an audience
// scope tag. Deferred alongside the metric source-tagging contract — both
// are proto-wire changes tracked by the same issue ("gRPC: trusted metric
// audience classification at registration"), which adds an `audience` field
// to `MetricDefinition` and validates `(module_id, name)` at ingestion. The
// span variant of that work will extend the same registry-driven scope so
// `is_operator_span` can derive its answer from the registered span schema
// instead of the current all-spans-operator constant.
fn is_operator_span(_span: &SpanData) -> bool {
    true
}

/// Aggregated telemetry snapshot from a single analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// When this snapshot was taken (unix ms).
    pub timestamp_ms: u64,
    /// Registered metric definitions keyed by name.
    pub definitions: HashMap<String, MetricDefinition>,
    /// All recorded data points.
    pub data_points: Vec<MetricDataPoint>,
    /// All recorded spans.
    pub spans: Vec<SpanData>,
    /// User-facing summary (finding counts, durations, scores).
    pub user_summary: UserSummary,
    /// Operator summary (call latencies, error rates).
    pub operator_summary: OperatorSummary,
    /// Names of data points that arrived on the UNTRUSTED external ingestion
    /// path (the gRPC `record_metrics` handler, via
    /// [`TelemetryCollector::record_untrusted_data_points`]). The projection
    /// in [`Self::project_for_audience`] forces every point whose name is in
    /// this set to the unclassified branch — admitted only under
    /// [`TelemetryAudience::On`] — REGARDLESS of how its name classifies via
    /// [`metric_names::is_operator`] / [`metric_names::is_known_user`]. That
    /// is what closes the privacy boundary: an external plugin cannot cross
    /// `user-only` (or `operator-only`) by spoofing a trusted metric name,
    /// whether a `chaffra.module.<id>.<key>` shape or an exact `KNOWN_USER`
    /// name like `chaffra.analysis.findings_total`.
    ///
    /// Provenance, not name, is the trust signal — this is the bounded form
    /// of the gRPC-ingress audience derivation tracked by issue #45.
    ///
    /// `#[serde(skip)]`: this set is internal projection metadata, never part
    /// of the on-disk snapshot wire contract. It is consumed during
    /// projection and must never be serialized — emitting it would itself
    /// disclose which external module names were seen. On deserialization it
    /// defaults to empty (no untrusted names known for a reloaded snapshot),
    /// which is the safe direction: a reloaded snapshot is already projected.
    #[serde(skip)]
    pub untrusted_runtime: HashSet<String>,
}

/// User-facing telemetry summary included in analysis output.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserSummary {
    /// Total analysis duration in milliseconds.
    pub analysis_duration_ms: u64,
    /// Total files analyzed.
    pub files_total: u64,
    /// Total findings by severity.
    pub findings_by_severity: HashMap<String, u64>,
    /// Total findings by module.
    pub findings_by_module: HashMap<String, u64>,
    /// Per-module breakdown.
    pub module_summaries: HashMap<String, ModuleSummary>,
}

/// Per-module summary for user-facing output.
///
/// Privacy note: the `register_core_metrics` completeness test
/// (`test_every_core_metric_is_classified`) guards only the set of registered
/// metric NAMES — it asserts every name lands in either `metric_names::OPERATOR`
/// or `KNOWN_USER_METRICS`. It does NOT guard additions of new FIELDS to this
/// struct: a new field has no metric name to classify, so it bypasses the test
/// entirely. Whenever a field is added here, audit `project_for_audience`
/// explicitly to decide whether the field is user-facing (kept as-is under
/// user-only), operator-derived (must be scrubbed under user-only, like
/// `duration_ms`), or operator-only (drop the whole entry).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleSummary {
    /// Duration of this module's analysis in ms.
    pub duration_ms: u64,
    /// Number of findings.
    pub finding_count: u64,
    /// Module-specific metrics (e.g. health_score, clone_count).
    pub metrics: HashMap<String, f64>,
}

/// Operator-level telemetry sunk to backends.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorSummary {
    /// Per-module call duration in ms.
    pub module_call_durations: HashMap<String, u64>,
    /// Per-module error counts.
    pub module_error_counts: HashMap<String, u64>,
}

impl TelemetrySnapshot {
    /// Project this snapshot down to exactly what the given audience is allowed
    /// to see, consuming the snapshot and returning the projected one. This is
    /// the privacy boundary: it MUST be applied before any filtering,
    /// aggregation, persistence, history recording, or backend emission so that
    /// operator-only fields never cross a user-facing boundary even temporarily.
    ///
    /// Taking `self` by value avoids a defensive deep clone of the whole
    /// snapshot on the per-run emission hot path: every caller already owns a
    /// freshly produced snapshot, so the projection filters and moves the
    /// retained data instead of cloning it.
    ///
    /// Scope is classified at the field level: operator data points
    /// ([`metric_names::is_operator`]), spans ([`is_operator_span`] — all spans are
    /// module execution traces, hence operator-level), and operator metric
    /// DEFINITIONS are all gated on the operator scope. Keeping operator
    /// definitions out of a user-only payload matters too: the definition
    /// catalogue itself discloses which operator metrics exist.
    ///
    /// Semantics for every audience mode:
    /// - [`TelemetryAudience::On`]: keep everything (user + operator).
    /// - [`TelemetryAudience::UserOnly`]: drop `operator_summary`, every
    ///   operator-only data point, every span, and every operator-only
    ///   definition; keep the user summary and user-facing data points/definitions,
    ///   but scrub the operator-derived per-module timing
    ///   (`user_summary.module_summaries[*].duration_ms`) out of the retained
    ///   user summary so it cannot leak through the user-facing field.
    /// - [`TelemetryAudience::OperatorOnly`]: drop `user_summary`; keep the
    ///   operator summary and all data points/spans/definitions.
    /// - [`TelemetryAudience::Off`]: drop both summaries and all data
    ///   points/spans/definitions, leaving only the timestamp shell.
    #[must_use]
    pub fn project_for_audience(self, audience: TelemetryAudience) -> Self {
        let keep_user = audience.user_enabled();
        let keep_operator = audience.operator_enabled();

        // Classification is three-way, not two-way: every name is either
        // OPERATOR (gated on the operator scope), KNOWN_USER (gated on the
        // user scope), or UNCLASSIFIED. A previous version of this filter
        // collapsed UNCLASSIFIED into the user branch (`else => keep_user`),
        // which was fail-OPEN at the privacy boundary: a runtime/external
        // metric whose name was neither in `OPERATOR` nor `KNOWN_USER` would
        // cross the user-only boundary unchallenged. The completeness test
        // catches that for REGISTERED definitions, but runtime data points
        // from plugins or future producers were unguarded.
        //
        // The fix is fail-CLOSED: an unclassified metric is admitted only
        // under `On` (the unrestricted scope: BOTH user and operator scopes
        // enabled). Under `user-only` it is dropped — there is no explicit
        // user scope on the metric, so it cannot cross a user-only boundary.
        // Under `operator-only` it is dropped for symmetry — operator-only is
        // a SPECIFIC scope, not a catch-all. Under `Off` it is dropped along
        // with everything else.
        //
        // PROVENANCE OVERRIDES NAME. A data point whose name arrived on the
        // untrusted external gRPC ingress (`untrusted_runtime`) is forced to
        // the unclassified branch REGARDLESS of how its name classifies. An
        // external plugin therefore cannot cross `user-only` (or
        // `operator-only`) by spoofing a trusted metric name — neither a
        // `chaffra.module.<id>.<key>` shape nor an exact `KNOWN_USER` name
        // like `chaffra.analysis.findings_total`. Name-based classification
        // (`is_operator` / `is_known_user`) is consulted ONLY for points from
        // trusted in-process producers. If a name is emitted by BOTH a
        // trusted producer and an adversarial plugin in the same run, it is
        // in `untrusted_runtime` and both points fail closed — the safe
        // direction, since the projection cannot tell the two apart by name
        // (the per-point source tagging that would is issue #45).
        let untrusted = &self.untrusted_runtime;
        let admit = |name: &str| -> bool {
            if untrusted.contains(name) {
                // Untrusted provenance: unclassified, admit only under `On`.
                keep_user && keep_operator
            } else if metric_names::is_operator(name) {
                keep_operator
            } else if metric_names::is_known_user(name) {
                keep_user
            } else {
                // Unclassified: require BOTH scopes (i.e. `On`).
                keep_user && keep_operator
            }
        };

        let data_points = self
            .data_points
            .into_iter()
            .filter(|dp| admit(&dp.name))
            .collect();

        // Spans are operator-scoped: retain them only when the operator scope
        // is enabled (covers both `Off`, which keeps neither scope, and
        // `user-only`, which must not leak module trace/timing spans).
        let spans = if keep_operator {
            self.spans.into_iter().filter(is_operator_span).collect()
        } else {
            Vec::new()
        };

        // Definitions are kept per-scope too: a user-facing definition survives
        // whenever the user scope is on, an operator definition only when the
        // operator scope is on. Under `Off` neither scope is enabled, so the
        // catalogue is emptied. Definitions classify with the same three-way
        // admit rule as data points: an unregistered/unclassified definition
        // is admitted only when BOTH scopes are enabled (i.e. `On`).
        let definitions = self
            .definitions
            .into_iter()
            .filter(|(name, _)| admit(name))
            .collect();

        // The user summary survives whenever the user scope is on, but it carries
        // one operator-derived field per module: `ModuleSummary.duration_ms` is
        // the same per-module analysis timing as
        // `operator_summary.module_call_durations` (named
        // `chaffra.module.call_duration_ms`, an OPERATOR metric). So when the
        // operator scope is off, that timing must be scrubbed out of the retained
        // user summary too — otherwise it leaks via `user_summary` even though
        // `operator_summary` was dropped.
        //
        // The set of `module_summaries` KEYS is itself operator-scope information:
        // the keys disclose which modules were composed into the pipeline. A
        // module that ran but produced no findings AND no per-module metrics has
        // no user-facing payload — its only contribution to the user summary was
        // the duration we just scrubbed. Keeping such an entry as
        // `{duration_ms: 0, finding_count: 0, metrics: {}}` would still leak the
        // executed-module name. So under user-only we drop those payload-empty
        // entries entirely; entries with findings (user-facing analysis result)
        // or per-module metrics (user-facing analysis output like `health_score`)
        // are kept because those carry signal the user is owed.
        //
        // `finding_count`, `metrics` (health_score/clone_count — user-facing
        // analysis results), and the top-level `analysis_duration_ms` (the user
        // headline) are NOT operator-derived and are kept. The
        // `register_core_metrics` completeness test does NOT guard
        // operator-derived FIELDS on this struct (only metric NAMES); a new
        // operator-derived field requires updating this projection by hand —
        // see the privacy note on `ModuleSummary`.
        let user_summary = if keep_user {
            let mut summary = self.user_summary;
            if !keep_operator {
                for module in summary.module_summaries.values_mut() {
                    module.duration_ms = 0;
                }
                summary
                    .module_summaries
                    .retain(|_, m| m.finding_count != 0 || !m.metrics.is_empty());
            }
            summary
        } else {
            UserSummary::default()
        };

        Self {
            timestamp_ms: self.timestamp_ms,
            definitions,
            data_points,
            spans,
            user_summary,
            operator_summary: if keep_operator {
                self.operator_summary
            } else {
                OperatorSummary::default()
            },
            // Preserve the untrusted-provenance set across projection so that
            // re-projecting an already-projected snapshot classifies
            // identically. It is `#[serde(skip)]`, so it never reaches any
            // serialized output regardless.
            untrusted_runtime: self.untrusted_runtime,
        }
    }
}

/// Thread-safe telemetry collector.
///
/// Modules call `register_metrics`, `record_data_point`, and `record_span`
/// during analysis. After the run, `snapshot()` returns the aggregated state.
#[derive(Debug, Clone)]
pub struct TelemetryCollector {
    inner: Arc<Mutex<CollectorInner>>,
    config: TelemetryConfig,
}

#[derive(Debug, Default)]
struct CollectorInner {
    definitions: HashMap<String, MetricDefinition>,
    data_points: Vec<MetricDataPoint>,
    spans: Vec<SpanData>,
    module_durations: HashMap<String, u64>,
    module_errors: HashMap<String, u64>,
    module_findings: HashMap<String, u64>,
    findings_by_severity: HashMap<String, u64>,
    files_total: u64,
    analysis_start_ms: u64,
    finding_fingerprints: HashSet<crate::churn::FindingFingerprint>,
    /// Names of data points received on the UNTRUSTED external gRPC ingress
    /// (`record_untrusted_data_points`). Handed to
    /// `TelemetrySnapshot::untrusted_runtime` at snapshot time so the
    /// projection forces these names to fail closed at every restricted
    /// audience boundary regardless of how the name classifies. Empty for a
    /// run with no external module metric submissions (the common case).
    untrusted_runtime: HashSet<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl TelemetryCollector {
    /// Create a new collector with the given configuration.
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CollectorInner {
                analysis_start_ms: now_ms(),
                ..Default::default()
            })),
            config,
        }
    }

    /// Create a collector with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(TelemetryConfig::default())
    }

    /// Get the current configuration.
    pub fn config(&self) -> &TelemetryConfig {
        &self.config
    }

    /// Register metric definitions from a module.
    pub fn register_metrics(
        &self,
        _module_id: &str,
        definitions: Vec<MetricDefinition>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        for def in definitions {
            inner.definitions.insert(def.name.clone(), def);
        }
        Ok(())
    }

    /// Record a single metric data point.
    pub fn record_data_point(&self, point: MetricDataPoint) {
        let mut inner = self.inner.lock().unwrap();
        inner.data_points.push(point);
    }

    /// Record multiple metric data points from a TRUSTED in-process producer
    /// (the parse-cache flush, churn metrics, the CLI telemetry-test point).
    /// Names recorded here are classified by `metric_names` at projection.
    /// External/plugin submissions must NOT use this method — see
    /// [`Self::record_untrusted_data_points`].
    pub fn record_data_points(&self, points: Vec<MetricDataPoint>) {
        let mut inner = self.inner.lock().unwrap();
        inner.data_points.extend(points);
    }

    /// Record data points received on the UNTRUSTED external ingestion path
    /// (the gRPC `record_metrics` handler — external module containers).
    ///
    /// Each point's name is recorded in `untrusted_runtime` so the snapshot
    /// projection forces it to fail closed at every restricted audience
    /// boundary: an external module cannot cross `user-only` or
    /// `operator-only` by naming its metric after a trusted user-facing or
    /// operator metric. The points still land in `data_points` (so they are
    /// emitted under `On`, the unrestricted audience) — provenance gates the
    /// RESTRICTED boundaries, not collection itself.
    ///
    /// TODO(#45): the per-name `untrusted_runtime` set is the bounded
    /// mitigation. The durable fix derives audience server-side from a
    /// trusted `(module_id, name)` registry at this ingress (an `audience`
    /// field on `MetricDefinition`), which also resolves the name-collision
    /// case where a trusted producer and a plugin share a metric name.
    pub fn record_untrusted_data_points(&self, points: Vec<MetricDataPoint>) {
        let mut inner = self.inner.lock().unwrap();
        for p in &points {
            inner.untrusted_runtime.insert(p.name.clone());
        }
        inner.data_points.extend(points);
    }

    /// Record a span.
    pub fn record_span(&self, span: SpanData) {
        let mut inner = self.inner.lock().unwrap();
        inner.spans.push(span);
    }

    /// Record multiple spans.
    pub fn record_spans(&self, spans: Vec<SpanData>) {
        let mut inner = self.inner.lock().unwrap();
        inner.spans.extend(spans);
    }

    /// Record a module call duration (called by the core after each module runs).
    pub fn record_module_call(&self, module_id: &str, duration_ms: u64, had_error: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .module_durations
            .insert(module_id.to_owned(), duration_ms);
        if had_error {
            *inner.module_errors.entry(module_id.to_owned()).or_insert(0) += 1;
        }

        // Record as data points.
        let ts = now_ms();
        inner.data_points.push(MetricDataPoint {
            name: metric_names::MODULE_CALL_DURATION_MS.to_owned(),
            value: duration_ms as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });

        if had_error {
            let error_count = inner.module_errors.get(module_id).copied().unwrap_or(1);
            inner.data_points.push(MetricDataPoint {
                name: metric_names::MODULE_ERROR_TOTAL.to_owned(),
                value: error_count as f64,
                labels: {
                    let mut m = HashMap::new();
                    m.insert("module".to_owned(), module_id.to_owned());
                    m
                },
                timestamp_ms: ts,
            });
        }
    }

    /// Record findings from a module (called by the core after each module runs).
    pub fn record_module_findings(
        &self,
        module_id: &str,
        finding_count: u64,
        severity_counts: &HashMap<String, u64>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner
            .module_findings
            .insert(module_id.to_owned(), finding_count);
        for (severity, count) in severity_counts {
            *inner
                .findings_by_severity
                .entry(severity.clone())
                .or_insert(0) += count;
        }

        let ts = now_ms();
        inner.data_points.push(MetricDataPoint {
            name: "chaffra.analysis.findings_total".to_owned(),
            value: finding_count as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });

        for (severity, count) in severity_counts {
            inner.data_points.push(MetricDataPoint {
                name: "chaffra.analysis.findings_by_severity".to_owned(),
                value: *count as f64,
                labels: {
                    let mut m = HashMap::new();
                    m.insert("module".to_owned(), module_id.to_owned());
                    m.insert("severity".to_owned(), severity.clone());
                    m
                },
                timestamp_ms: ts,
            });
        }
    }

    /// Set total files analyzed.
    pub fn set_files_total(&self, count: u64) {
        let mut inner = self.inner.lock().unwrap();
        inner.files_total = count;
    }

    /// Record a per-module summary metric (e.g. health_score, clone_count).
    ///
    /// This is a TRUSTED in-process producer: built-in modules run in-process
    /// and call this directly. The emitted `chaffra.module.<id>.<key>` name
    /// classifies as user-facing by shape in `metric_names::is_known_user`,
    /// so it survives `user-only`. Provenance is implicit — the name is NOT
    /// added to `untrusted_runtime`, so the projection trusts its name
    /// classification. (An external plugin emitting the identical shape goes
    /// through `record_untrusted_data_points` and fails closed.)
    pub fn record_module_summary_metric(&self, module_id: &str, key: &str, value: f64) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: format!("chaffra.module.{module_id}.{key}"),
            value,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Take a snapshot of all collected telemetry.
    pub fn snapshot(&self) -> TelemetrySnapshot {
        let inner = self.inner.lock().unwrap();
        let now = now_ms();
        let analysis_duration = now.saturating_sub(inner.analysis_start_ms);

        // Build per-module summaries.
        let mut module_summaries = HashMap::new();
        for (module_id, &duration) in &inner.module_durations {
            let finding_count = inner.module_findings.get(module_id).copied().unwrap_or(0);

            // Collect module-specific metrics from data points. Points whose
            // name arrived on the untrusted external ingress are skipped:
            // `user_summary` is a user-facing field, so an external plugin
            // must not be able to inject a `chaffra.module.<id>.<key>` value
            // here (it would otherwise bypass the projection's data_points
            // provenance gate, which filters the top-level list but not this
            // derived map). Trusted in-process producers
            // (`record_module_summary_metric`) are not in `untrusted_runtime`
            // and pass through.
            let prefix = format!("chaffra.module.{module_id}.");
            let mut metrics = HashMap::new();
            for dp in &inner.data_points {
                if inner.untrusted_runtime.contains(&dp.name) {
                    continue;
                }
                if let Some(key) = dp.name.strip_prefix(&prefix) {
                    metrics.insert(key.to_owned(), dp.value);
                }
            }

            module_summaries.insert(
                module_id.clone(),
                ModuleSummary {
                    duration_ms: duration,
                    finding_count,
                    metrics,
                },
            );
        }

        TelemetrySnapshot {
            timestamp_ms: now,
            definitions: inner.definitions.clone(),
            data_points: inner.data_points.clone(),
            spans: inner.spans.clone(),
            user_summary: UserSummary {
                analysis_duration_ms: analysis_duration,
                files_total: inner.files_total,
                findings_by_severity: inner.findings_by_severity.clone(),
                findings_by_module: inner.module_findings.clone(),
                module_summaries,
            },
            operator_summary: OperatorSummary {
                module_call_durations: inner.module_durations.clone(),
                module_error_counts: inner.module_errors.clone(),
            },
            untrusted_runtime: inner.untrusted_runtime.clone(),
        }
    }

    /// Reset the collector for a new run.
    pub fn reset(&self) {
        let mut inner = self.inner.lock().unwrap();
        *inner = CollectorInner {
            analysis_start_ms: now_ms(),
            ..Default::default()
        };
    }

    /// Record a module load error.
    pub fn record_module_load_error(&self, module_id: &str, error_type: &str) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: metric_names::MODULE_LOAD_ERROR_TOTAL.to_owned(),
            value: 1.0,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m.insert("error_type".to_owned(), error_type.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Record a config parse error.
    pub fn record_config_parse_error(&self) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: metric_names::CONFIG_PARSE_ERROR_TOTAL.to_owned(),
            value: 1.0,
            labels: HashMap::new(),
            timestamp_ms: ts,
        });
    }

    /// Record a plugin (external module) connection error.
    pub fn record_plugin_connect_error(&self, module_id: &str) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: metric_names::PLUGIN_CONNECT_ERROR_TOTAL.to_owned(),
            value: 1.0,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Record per-module startup/initialization duration.
    pub fn record_module_startup(&self, module_id: &str, duration_ms: u64) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: metric_names::MODULE_STARTUP_DURATION_MS.to_owned(),
            value: duration_ms as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("module".to_owned(), module_id.to_owned());
                m
            },
            timestamp_ms: ts,
        });
    }

    /// Record total startup duration (all modules ready).
    pub fn record_startup_total(&self, duration_ms: u64) {
        let ts = now_ms();
        self.record_data_point(MetricDataPoint {
            name: metric_names::STARTUP_TOTAL_DURATION_MS.to_owned(),
            value: duration_ms as f64,
            labels: HashMap::new(),
            timestamp_ms: ts,
        });
    }

    /// Record finding churn metrics from a churn result.
    pub fn record_finding_churn(&self, churn: &crate::churn::ChurnResult) {
        let ts = now_ms();
        let points = vec![
            MetricDataPoint {
                name: "chaffra.findings.new".to_owned(),
                value: churn.new_count as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.findings.resolved".to_owned(),
                value: churn.resolved_count as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.findings.unchanged".to_owned(),
                value: churn.unchanged_count as f64,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
            MetricDataPoint {
                name: "chaffra.findings.churn_rate".to_owned(),
                value: churn.churn_rate,
                labels: HashMap::new(),
                timestamp_ms: ts,
            },
        ];
        self.record_data_points(points);
    }

    /// Store finding fingerprints produced by the current analysis run.
    pub fn set_finding_fingerprints(
        &self,
        fingerprints: HashSet<crate::churn::FindingFingerprint>,
    ) {
        let mut inner = self.inner.lock().unwrap();
        inner.finding_fingerprints = fingerprints;
    }

    /// Retrieve finding fingerprints stored during the current run.
    pub fn finding_fingerprints(&self) -> HashSet<crate::churn::FindingFingerprint> {
        let inner = self.inner.lock().unwrap();
        inner.finding_fingerprints.clone()
    }

    /// Register the core metric definitions.
    pub fn register_core_metrics(&self) {
        let defs = vec![
            MetricDefinition {
                name: "chaffra.analysis.duration_ms".to_owned(),
                kind: MetricKind::Histogram,
                description: "Total analysis duration".to_owned(),
                unit: "ms".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.analysis.files_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Total files analyzed".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.analysis.findings_total".to_owned(),
                kind: MetricKind::Counter,
                description: "Total findings per module".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.analysis.findings_by_severity".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings per module and severity".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: metric_names::MODULE_CALL_DURATION_MS.to_owned(),
                kind: MetricKind::Histogram,
                description: "Per-module call duration".to_owned(),
                unit: "ms".to_owned(),
            },
            MetricDefinition {
                name: metric_names::MODULE_ERROR_TOTAL.to_owned(),
                kind: MetricKind::Counter,
                description: "Per-module error count".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.new".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings not in previous run".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.resolved".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings in previous run but not current".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.unchanged".to_owned(),
                kind: MetricKind::Counter,
                description: "Findings present in both runs".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: "chaffra.findings.churn_rate".to_owned(),
                kind: MetricKind::Gauge,
                description: "Churn rate: new / (new + unchanged)".to_owned(),
                unit: "ratio".to_owned(),
            },
            MetricDefinition {
                name: metric_names::MODULE_LOAD_ERROR_TOTAL.to_owned(),
                kind: MetricKind::Counter,
                description: "Module load failures by module_id and error_type".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: metric_names::CONFIG_PARSE_ERROR_TOTAL.to_owned(),
                kind: MetricKind::Counter,
                description: "Config parse failures".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: metric_names::PLUGIN_CONNECT_ERROR_TOTAL.to_owned(),
                kind: MetricKind::Counter,
                description: "External module gRPC connection failures".to_owned(),
                unit: "count".to_owned(),
            },
            MetricDefinition {
                name: metric_names::MODULE_STARTUP_DURATION_MS.to_owned(),
                kind: MetricKind::Histogram,
                description: "Per-module initialization time".to_owned(),
                unit: "ms".to_owned(),
            },
            MetricDefinition {
                name: metric_names::STARTUP_TOTAL_DURATION_MS.to_owned(),
                kind: MetricKind::Gauge,
                description: "Total time from process start to all modules ready".to_owned(),
                unit: "ms".to_owned(),
            },
        ];
        let _ = self.register_metrics("core", defs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector_basic() {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(10);
        collector.record_module_call("dead-code", 42, false);

        let mut severity_counts = HashMap::new();
        severity_counts.insert("warning".to_owned(), 3);
        collector.record_module_findings("dead-code", 3, &severity_counts);

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.user_summary.files_total, 10);
        assert_eq!(
            snapshot.user_summary.findings_by_module.get("dead-code"),
            Some(&3)
        );
        assert_eq!(
            snapshot
                .operator_summary
                .module_call_durations
                .get("dead-code"),
            Some(&42)
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.analysis.duration_ms")
        );
    }

    #[test]
    fn test_collector_data_points() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_data_point(MetricDataPoint {
            name: "test.metric".to_owned(),
            value: 1.0,
            labels: HashMap::new(),
            timestamp_ms: 100,
        });
        collector.record_data_points(vec![
            MetricDataPoint {
                name: "test.metric".to_owned(),
                value: 2.0,
                labels: HashMap::new(),
                timestamp_ms: 200,
            },
            MetricDataPoint {
                name: "test.metric".to_owned(),
                value: 3.0,
                labels: HashMap::new(),
                timestamp_ms: 300,
            },
        ]);

        let snapshot = collector.snapshot();
        // 3 explicit + 0 implicit
        assert!(snapshot.data_points.len() >= 3);
    }

    #[test]
    fn test_collector_spans() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_span(SpanData {
            name: "test".to_owned(),
            trace_id: "t1".to_owned(),
            span_id: "s1".to_owned(),
            parent_span_id: String::new(),
            start_time_ms: 100,
            end_time_ms: 200,
            attributes: HashMap::new(),
            status: "ok".to_owned(),
        });

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.spans.len(), 1);
        assert_eq!(snapshot.spans[0].name, "test");
    }

    #[test]
    fn test_collector_reset() {
        let collector = TelemetryCollector::with_defaults();
        collector.set_files_total(5);
        collector.record_module_call("test", 10, false);
        collector.reset();

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.user_summary.files_total, 0);
        assert!(snapshot.data_points.is_empty());
    }

    #[test]
    fn test_collector_module_summary_metric() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("complexity", 50, false);
        collector.record_module_summary_metric("complexity", "health_score", 85.0);
        collector.record_module_summary_metric("complexity", "cyclomatic_avg", 4.2);

        let snapshot = collector.snapshot();
        let summary = &snapshot.user_summary.module_summaries["complexity"];
        assert_eq!(summary.duration_ms, 50);
        assert!((summary.metrics["health_score"] - 85.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_collector_error_tracking() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("failing", 10, true);
        collector.record_module_call("failing", 20, true);

        let snapshot = collector.snapshot();
        assert_eq!(
            snapshot.operator_summary.module_error_counts.get("failing"),
            Some(&2)
        );
    }

    #[test]
    fn test_collector_module_load_error() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_load_error("security", "missing_dependency");
        let snapshot = collector.snapshot();
        let dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.module.load_error_total")
            .unwrap();
        assert!((dp.value - 1.0).abs() < f64::EPSILON);
        assert_eq!(dp.labels.get("module").unwrap(), "security");
        assert_eq!(dp.labels.get("error_type").unwrap(), "missing_dependency");
    }

    #[test]
    fn test_collector_config_parse_error() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_config_parse_error();
        let snapshot = collector.snapshot();
        assert!(
            snapshot
                .data_points
                .iter()
                .any(|p| p.name == "chaffra.config.parse_error_total")
        );
    }

    #[test]
    fn test_collector_plugin_connect_error() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_plugin_connect_error("fastapi-module");
        let snapshot = collector.snapshot();
        let dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.plugin.connect_error_total")
            .unwrap();
        assert_eq!(dp.labels.get("module").unwrap(), "fastapi-module");
    }

    #[test]
    fn test_collector_module_startup() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_startup("dead-code", 15);
        collector.record_module_startup("complexity", 8);
        let snapshot = collector.snapshot();
        let startup_points: Vec<_> = snapshot
            .data_points
            .iter()
            .filter(|p| p.name == "chaffra.module.startup_duration_ms")
            .collect();
        assert_eq!(startup_points.len(), 2);
    }

    #[test]
    fn test_collector_startup_total() {
        let collector = TelemetryCollector::with_defaults();
        collector.record_startup_total(250);
        let snapshot = collector.snapshot();
        let dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.startup.total_duration_ms")
            .unwrap();
        assert!((dp.value - 250.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_collector_finding_churn() {
        let collector = TelemetryCollector::with_defaults();
        let churn = crate::churn::ChurnResult {
            new_count: 3,
            resolved_count: 1,
            unchanged_count: 5,
            churn_rate: 0.375,
        };
        collector.record_finding_churn(&churn);
        let snapshot = collector.snapshot();

        let new_dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.findings.new")
            .unwrap();
        assert!((new_dp.value - 3.0).abs() < f64::EPSILON);

        let rate_dp = snapshot
            .data_points
            .iter()
            .find(|p| p.name == "chaffra.findings.churn_rate")
            .unwrap();
        assert!((rate_dp.value - 0.375).abs() < f64::EPSILON);
    }

    #[test]
    fn test_core_metrics_include_phase13() {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        let snapshot = collector.snapshot();
        assert!(snapshot.definitions.contains_key("chaffra.findings.new"));
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.findings.churn_rate")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.module.load_error_total")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.module.startup_duration_ms")
        );
        assert!(
            snapshot
                .definitions
                .contains_key("chaffra.startup.total_duration_ms")
        );
    }

    /// Build a snapshot that contains both user-facing and operator-only
    /// data so projection can be checked exhaustively.
    fn snapshot_with_mixed_metrics() -> TelemetrySnapshot {
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.set_files_total(7);
        // Operator-only metrics (call duration + error).
        collector.record_module_call("dead-code", 42, true);
        collector.record_module_startup("dead-code", 5);
        collector.record_startup_total(120);
        collector.record_plugin_connect_error("fastapi");
        collector.record_config_parse_error();
        // User-facing metrics (findings).
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 2);
        collector.record_module_findings("dead-code", 2, &sev);
        collector.record_module_summary_metric("dead-code", "unused_functions", 3.0);
        // Operator-only parse-cache metric (memory/eviction pressure).
        collector.record_data_point(MetricDataPoint {
            name: metric_names::PARSE_CACHE_SIZE_BYTES.to_owned(),
            value: 4096.0,
            labels: HashMap::new(),
            timestamp_ms: 1,
        });
        collector.record_span(SpanData {
            name: "dead-code.analyze".to_owned(),
            trace_id: "t".to_owned(),
            span_id: "s".to_owned(),
            parent_span_id: String::new(),
            start_time_ms: 1,
            end_time_ms: 2,
            attributes: HashMap::new(),
            status: "ok".to_owned(),
        });
        collector.snapshot()
    }

    #[test]
    fn test_projection_on_keeps_everything() {
        let snap = snapshot_with_mixed_metrics().project_for_audience(TelemetryAudience::On);
        assert!(!snap.operator_summary.module_call_durations.is_empty());
        assert_eq!(snap.user_summary.files_total, 7);
        assert!(!snap.spans.is_empty());
        assert!(!snap.definitions.is_empty());
        // Both an operator metric and a user metric survive.
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == metric_names::MODULE_CALL_DURATION_MS)
        );
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == "chaffra.analysis.findings_total")
        );
        // Both an operator definition and a user definition survive.
        assert!(
            snap.definitions
                .contains_key(metric_names::MODULE_ERROR_TOTAL)
        );
        assert!(
            snap.definitions
                .contains_key("chaffra.analysis.findings_total")
        );
    }

    #[test]
    fn test_projection_user_only_drops_operator() {
        let snap = snapshot_with_mixed_metrics().project_for_audience(TelemetryAudience::UserOnly);
        // Operator summary is wiped.
        assert!(snap.operator_summary.module_call_durations.is_empty());
        assert!(snap.operator_summary.module_error_counts.is_empty());
        // User summary survives.
        assert_eq!(snap.user_summary.files_total, 7);
        // Spans are operator-scoped (module traces): none may cross the boundary.
        assert!(
            snap.spans.is_empty(),
            "operator-scoped spans leaked under user-only projection"
        );
        // No operator-only data point may cross the boundary, including the
        // parse-cache pressure metric.
        for dp in &snap.data_points {
            assert!(
                !metric_names::is_operator(&dp.name),
                "operator metric {} leaked under user-only projection",
                dp.name
            );
        }
        assert!(
            !snap
                .data_points
                .iter()
                .any(|p| p.name == metric_names::PARSE_CACHE_SIZE_BYTES),
            "parse-cache metric must be withheld under user-only"
        );
        // Operator metric DEFINITIONS must not be disclosed either...
        for op in metric_names::OPERATOR {
            assert!(
                !snap.definitions.contains_key(*op),
                "operator definition {op} leaked under user-only projection"
            );
        }
        // ...while user-facing data points and definitions remain.
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == "chaffra.analysis.findings_total")
        );
        assert!(
            snap.definitions
                .contains_key("chaffra.analysis.findings_total")
        );
    }

    #[test]
    fn test_projection_user_only_scrubs_module_timing_from_user_summary() {
        // Operator per-module timing also rides inside `user_summary` via
        // `module_summaries[*].duration_ms` (the same value as
        // `operator_summary.module_call_durations`, an OPERATOR metric). Under
        // user-only that timing must be scrubbed to 0, while the user-facing
        // finding_count and module metrics (e.g. health_score) survive. This test
        // inspects `user_summary.module_summaries` directly — the residual leak
        // round-2 missed because it only checked `operator_summary` and data points.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.record_module_call("complexity", 73, false);
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 4);
        collector.record_module_findings("complexity", 4, &sev);
        collector.record_module_summary_metric("complexity", "health_score", 88.0);
        let raw = collector.snapshot();
        // Sanity: the raw snapshot carries the per-module timing.
        assert_eq!(
            raw.user_summary.module_summaries["complexity"].duration_ms,
            73
        );
        let top_duration = raw.user_summary.analysis_duration_ms;

        let snap = raw.project_for_audience(TelemetryAudience::UserOnly);
        let summary = &snap.user_summary.module_summaries["complexity"];
        // Operator-derived per-module timing is scrubbed...
        assert_eq!(
            summary.duration_ms, 0,
            "operator per-module timing leaked via user_summary under user-only"
        );
        // ...but the user-facing finding count and module metric survive.
        assert_eq!(summary.finding_count, 4);
        assert!((summary.metrics["health_score"] - 88.0).abs() < f64::EPSILON);
        // ...and the top-level user headline duration is preserved.
        assert_eq!(snap.user_summary.analysis_duration_ms, top_duration);
    }

    #[test]
    fn test_projection_user_only_prunes_payload_empty_module_entries() {
        // 1B: `module_summaries` KEYS disclose the executed-module set — that's
        // operator-scope pipeline composition information. After the timing
        // scrub, an entry like `{duration_ms: 0, finding_count: 0, metrics: {}}`
        // still leaks the module name. Under user-only, drop entries that have
        // no user-facing signal (no findings AND no metrics); keep entries that
        // do (findings or per-module metrics).
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        // `security` ran but produced ZERO findings and no per-module metrics.
        collector.record_module_call("security", 12, false);
        // `complexity` ran and emitted a user-facing per-module metric, but no findings.
        collector.record_module_call("complexity", 17, false);
        collector.record_module_summary_metric("complexity", "health_score", 92.0);
        // `dead-code` ran and produced a finding.
        collector.record_module_call("dead-code", 9, false);
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 1);
        collector.record_module_findings("dead-code", 1, &sev);

        let raw = collector.snapshot();
        // Sanity: all three modules are in the raw map.
        assert!(raw.user_summary.module_summaries.contains_key("security"));
        assert!(raw.user_summary.module_summaries.contains_key("complexity"));
        assert!(raw.user_summary.module_summaries.contains_key("dead-code"));

        let user_only = raw.project_for_audience(TelemetryAudience::UserOnly);
        // The payload-empty `security` entry is dropped — its key would leak the
        // executed-module set otherwise.
        assert!(
            !user_only
                .user_summary
                .module_summaries
                .contains_key("security"),
            "payload-empty module entry leaked the executed-module set under user-only"
        );
        // `complexity` survives (has a per-module metric), with timing scrubbed.
        let complexity = &user_only.user_summary.module_summaries["complexity"];
        assert_eq!(complexity.duration_ms, 0);
        assert!((complexity.metrics["health_score"] - 92.0).abs() < f64::EPSILON);
        // `dead-code` survives (has findings), with timing scrubbed.
        let dc = &user_only.user_summary.module_summaries["dead-code"];
        assert_eq!(dc.duration_ms, 0);
        assert_eq!(dc.finding_count, 1);
    }

    #[test]
    fn test_projection_on_and_operator_only_preserve_module_summaries_keys() {
        // 1B: under On (operator scope enabled), the payload-empty entry must be
        // preserved verbatim — pruning is strictly a user-only privacy step.
        // Under OperatorOnly the user summary is wiped wholesale (existing
        // behaviour), so the pruning rule is irrelevant there; we assert both.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.record_module_call("security", 12, false);
        collector.record_module_call("complexity", 17, false);
        collector.record_module_summary_metric("complexity", "health_score", 92.0);

        let on = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::On);
        // Payload-empty entry preserved when the operator scope is enabled.
        let sec = &on.user_summary.module_summaries["security"];
        assert_eq!(sec.duration_ms, 12);
        assert_eq!(sec.finding_count, 0);
        assert!(sec.metrics.is_empty());

        let op_only = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::OperatorOnly);
        // OperatorOnly wipes the user summary wholesale; no module_summaries.
        assert!(op_only.user_summary.module_summaries.is_empty());
    }

    #[test]
    fn test_projection_operator_scopes_preserve_module_timing() {
        // Under On and operator-only the per-module timing inside the user
        // summary is preserved (operator scope is enabled). operator-only wipes
        // the user summary wholesale, so only On retains a populated user summary.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.record_module_call("complexity", 73, false);
        let on = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::On);
        assert_eq!(
            on.user_summary.module_summaries["complexity"].duration_ms, 73,
            "On must preserve per-module timing in the user summary"
        );
    }

    #[test]
    fn test_projection_operator_only_drops_user_summary() {
        let snap =
            snapshot_with_mixed_metrics().project_for_audience(TelemetryAudience::OperatorOnly);
        // User summary is wiped...
        assert_eq!(snap.user_summary.files_total, 0);
        assert!(snap.user_summary.findings_by_module.is_empty());
        // ...but operator data survives, including spans and operator definitions.
        assert!(!snap.operator_summary.module_call_durations.is_empty());
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == metric_names::MODULE_CALL_DURATION_MS)
        );
        assert!(
            !snap.spans.is_empty(),
            "operator-scoped spans must survive under operator-only"
        );
        assert!(
            snap.definitions
                .contains_key(metric_names::MODULE_ERROR_TOTAL)
        );
    }

    #[test]
    fn test_projection_off_drops_everything() {
        let snap = snapshot_with_mixed_metrics().project_for_audience(TelemetryAudience::Off);
        assert!(snap.data_points.is_empty());
        assert!(snap.spans.is_empty());
        assert!(snap.definitions.is_empty());
        assert_eq!(snap.user_summary.files_total, 0);
        assert!(snap.operator_summary.module_call_durations.is_empty());
    }

    /// Classify a REGISTERED metric definition name into a known scope by
    /// EXACT membership of the two explicit sets. Returns `false` for a name
    /// that is in neither — i.e. an unclassified metric that would either leak
    /// (under the previous fail-open) or be silently dropped (under the new
    /// fail-closed projection). Pattern matching is intentionally omitted at
    /// the DEFINITIONS layer: a `chaffra.module.<x>.<y>`-shaped operator
    /// metric must be classified by adding it to `metric_names::OPERATOR`,
    /// not by passing through the per-module shape match. Per-module summary
    /// RUNTIME data points are admitted by shape in `is_known_user` (and
    /// gated by provenance in the projection), but they are never registered
    /// as DEFINITIONS, so this completeness guard does not see them.
    fn metric_is_classified(name: &str) -> bool {
        metric_names::is_operator(name) || metric_names::KNOWN_USER.contains(&name)
    }

    #[test]
    fn test_every_core_metric_is_classified() {
        // P2 completeness guard (fail-open mitigation): register the core metric
        // definitions and assert EVERY registered name lands in a known scope.
        // A future operator metric added to `register_core_metrics` but NOT to
        // `metric_names::OPERATOR` (and not a known-user name) would be silently
        // classified user-facing and leak under user-only — this test turns that
        // omission into a CI failure instead.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        let snap = collector.snapshot();
        assert!(
            !snap.definitions.is_empty(),
            "register_core_metrics produced no definitions"
        );
        for name in snap.definitions.keys() {
            assert!(
                metric_is_classified(name),
                "registered metric {name:?} is unclassified: it is in neither \
                 metric_names::OPERATOR nor KNOWN_USER_METRICS. Add it to \
                 OPERATOR (operator-scoped) or to KNOWN_USER_METRICS (user-facing) \
                 so it cannot leak under user-only."
            );
        }
    }

    #[test]
    fn test_completeness_guard_rejects_unclassified_metric() {
        // The guard must actually FAIL for an unknown metric, otherwise it would
        // pass vacuously and provide no protection.
        assert!(!metric_is_classified("chaffra.future.unregistered_metric"));
        // And it must still accept the two known scopes by exact name.
        assert!(metric_is_classified(metric_names::MODULE_CALL_DURATION_MS));
        assert!(metric_is_classified("chaffra.analysis.findings_total"));
    }

    #[test]
    fn test_completeness_guard_rejects_per_module_pattern_metric() {
        // 1A: a future operator-shaped name like `chaffra.module.host.dispatch_latency_ms`
        // — which matches the per-module summary shape `chaffra.module.<id>.<key>`
        // — must NOT be silently admitted as user-facing. Round-2 used a
        // permissive pattern (`starts_with("chaffra.module.") && >=3 dots`) that
        // would pass this name through; the round-3 fix removes that branch so
        // the operator-shaped name lands in neither set and the guard rejects it.
        let candidate = "chaffra.module.host.dispatch_latency_ms";
        assert!(
            !metric_is_classified(candidate),
            "operator-shaped per-module metric {candidate:?} must NOT be admitted \
             via a pattern; it has to be added to metric_names::OPERATOR explicitly. \
             A pattern-based fallback re-introduces the silent-acceptance failure \
             this test is here to prevent."
        );

        // And the same guard, exercised end-to-end against the registered set:
        // injecting such a name into the registered definitions makes the
        // completeness loop fail. We assert that on a synthetic snapshot built
        // by hand (no need to mutate the producer) — the snapshot path mirrors
        // exactly what `test_every_core_metric_is_classified` does.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector
            .register_metrics(
                "test",
                vec![MetricDefinition {
                    name: candidate.to_owned(),
                    kind: MetricKind::Histogram,
                    description: "fictitious operator metric".to_owned(),
                    unit: "ms".to_owned(),
                }],
            )
            .unwrap();
        let snap = collector.snapshot();
        let unclassified: Vec<&String> = snap
            .definitions
            .keys()
            .filter(|n| !metric_is_classified(n))
            .collect();
        assert_eq!(
            unclassified.len(),
            1,
            "exactly one unclassified name expected, got {unclassified:?}"
        );
        assert_eq!(unclassified[0], candidate);
    }

    #[test]
    fn test_projection_user_only_drops_unclassified_data_point() {
        // Fail-closed: a runtime data point whose name is in NEITHER
        // `metric_names::OPERATOR` NOR `metric_names::KNOWN_USER` (nor the
        // per-module summary shape) must not cross the user-only boundary.
        // Previously such a name was admitted by the `else => keep_user`
        // branch, leaking arbitrary external-plugin metrics under user-only.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        // Unclassified: not in OPERATOR, not in KNOWN_USER, not per-module
        // summary shaped. A plugin or future producer could legitimately emit
        // this; the classifier has no scope tag for it.
        collector.record_data_point(MetricDataPoint {
            name: "external.plugin.custom_metric".to_owned(),
            value: 42.0,
            labels: HashMap::new(),
            timestamp_ms: 1,
        });
        // A user-facing classified metric (control) — survives under user-only.
        let mut sev = HashMap::new();
        sev.insert("warning".to_owned(), 1);
        collector.record_module_findings("dead-code", 1, &sev);

        let snap = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::UserOnly);
        assert!(
            !snap
                .data_points
                .iter()
                .any(|p| p.name == "external.plugin.custom_metric"),
            "unclassified data point leaked under user-only (fail-open regression)"
        );
        // The classified user-facing metric is preserved.
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == "chaffra.analysis.findings_total"),
            "classified user-facing metric was dropped"
        );
    }

    #[test]
    fn test_projection_operator_only_drops_unclassified_data_point() {
        // Symmetric fail-closed at the operator boundary: an unclassified
        // metric is not implicitly operator-scoped either. Only `On` (both
        // scopes enabled) admits unclassified.
        let collector = TelemetryCollector::with_defaults();
        collector.register_core_metrics();
        collector.record_data_point(MetricDataPoint {
            name: "external.plugin.custom_metric".to_owned(),
            value: 42.0,
            labels: HashMap::new(),
            timestamp_ms: 1,
        });
        collector.record_module_call("dead-code", 7, false); // OPERATOR metric

        let snap = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::OperatorOnly);
        assert!(
            !snap
                .data_points
                .iter()
                .any(|p| p.name == "external.plugin.custom_metric"),
            "unclassified data point leaked under operator-only"
        );
        // The classified operator metric is preserved.
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == metric_names::MODULE_CALL_DURATION_MS),
            "classified operator metric was dropped"
        );
    }

    #[test]
    fn test_projection_on_admits_unclassified_data_point() {
        // `On` is the only audience that admits an unclassified metric:
        // BOTH scopes are enabled, so the "needs explicit scope" rule does
        // not gate. This keeps `On` as the genuine no-projection audience
        // for operators who want raw passthrough.
        let collector = TelemetryCollector::with_defaults();
        collector.record_data_point(MetricDataPoint {
            name: "external.plugin.custom_metric".to_owned(),
            value: 42.0,
            labels: HashMap::new(),
            timestamp_ms: 1,
        });
        let snap = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::On);
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == "external.plugin.custom_metric"),
            "On audience dropped an unclassified metric — On must pass everything"
        );
    }

    #[test]
    fn test_projection_user_only_drops_unclassified_definition() {
        // The same fail-closed rule covers DEFINITIONS: an unclassified
        // definition (one a plugin registers without listing in OPERATOR or
        // KNOWN_USER) must not appear in a user-only catalogue, otherwise
        // the catalogue itself discloses which unclassified metrics exist.
        let collector = TelemetryCollector::with_defaults();
        collector
            .register_metrics(
                "external-plugin",
                vec![MetricDefinition {
                    name: "external.plugin.unclassified_def".to_owned(),
                    kind: MetricKind::Counter,
                    description: "unclassified".to_owned(),
                    unit: "count".to_owned(),
                }],
            )
            .unwrap();
        let snap = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::UserOnly);
        assert!(
            !snap
                .definitions
                .contains_key("external.plugin.unclassified_def"),
            "unclassified definition leaked under user-only"
        );
    }

    #[test]
    fn test_projection_user_only_admits_per_module_summary_runtime_metric() {
        // Per-module summary RUNTIME data points (`chaffra.module.<id>.<key>`)
        // are produced by the TRUSTED in-process `record_module_summary_metric`
        // — they carry user-facing analysis output (health_score, clone_count,
        // etc.) and classify as user-facing by shape in `is_known_user`. They
        // are NOT in `untrusted_runtime`, so the projection trusts the name.
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_summary_metric("complexity", "health_score", 88.0);
        let snap = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::UserOnly);
        assert!(
            snap.data_points
                .iter()
                .any(|p| p.name == "chaffra.module.complexity.health_score"),
            "per-module summary metric was dropped under user-only"
        );
    }

    #[test]
    fn test_projection_provenance_overrides_name_for_spoofed_metrics() {
        // R3 fail-closed invariant: PROVENANCE overrides NAME. A point that
        // arrives on the untrusted external gRPC ingress
        // (`record_untrusted_data_points`, what the `record_metrics` handler
        // calls) must fail closed at every restricted boundary REGARDLESS of
        // how its name classifies — whether it spoofs a per-module summary
        // shape OR an exact `KNOWN_USER` name. Trusted in-process producers
        // pass by name.
        //
        // Cross-checked against all four audiences:
        // - On            → everything admitted (unrestricted)
        // - UserOnly      → only the trusted point (privacy boundary)
        // - OperatorOnly  → nothing user-facing (trusted user point dropped,
        //                   untrusted forced unclassified → user scope off)
        // - Off           → nothing
        let make_snapshot = || {
            let collector = TelemetryCollector::with_defaults();
            // Trusted: emitted via the in-process producer.
            collector.record_module_summary_metric("complexity", "health_score", 88.0);
            // Untrusted spoofs via the external gRPC ingress. Both a
            // per-module shape AND an exact KNOWN_USER name — the R2 fix only
            // closed the former; provenance closes both.
            collector.record_untrusted_data_points(vec![
                MetricDataPoint {
                    name: "chaffra.module.plugin.cache_size_bytes".to_owned(),
                    value: 1024.0,
                    labels: HashMap::new(),
                    timestamp_ms: 0,
                },
                MetricDataPoint {
                    // Exact KNOWN_USER name — the explicit-set spoof.
                    name: "chaffra.analysis.findings_total".to_owned(),
                    value: 999.0,
                    labels: HashMap::new(),
                    timestamp_ms: 0,
                },
            ]);
            collector.snapshot()
        };

        let trusted = "chaffra.module.complexity.health_score";
        let spoofed_shape = "chaffra.module.plugin.cache_size_bytes";
        let spoofed_known = "chaffra.analysis.findings_total";

        // (audience, trusted, spoofed_shape, spoofed_known)
        let cases = [
            (TelemetryAudience::On, true, true, true),
            (TelemetryAudience::UserOnly, true, false, false),
            (TelemetryAudience::OperatorOnly, false, false, false),
            (TelemetryAudience::Off, false, false, false),
        ];
        for (audience, want_trusted, want_shape, want_known) in cases {
            let snap = make_snapshot().project_for_audience(audience);
            let has = |n: &str| snap.data_points.iter().any(|p| p.name == n);
            assert_eq!(
                has(trusted),
                want_trusted,
                "{audience:?}: trusted per-module metric admit mismatch"
            );
            assert_eq!(
                has(spoofed_shape),
                want_shape,
                "{audience:?}: untrusted per-module-shaped spoof admit mismatch \
                 (true at a restricted boundary = fail-open)"
            );
            assert_eq!(
                has(spoofed_known),
                want_known,
                "{audience:?}: untrusted exact-KNOWN_USER-name spoof admit mismatch \
                 (true under user-only = the R2 residual fail-open)"
            );
        }
    }

    #[test]
    fn test_user_summary_metrics_map_excludes_untrusted_spoof() {
        // The user_summary.module_summaries[*].metrics map is built by
        // prefix-matching data point names — a parallel path to the top-level
        // data_points list. An untrusted plugin spoofing
        // `chaffra.module.complexity.<key>` must NOT inject a value into the
        // user-facing metrics map for the `complexity` module, even though a
        // (trusted) `record_module_call("complexity", ...)` gave that module a
        // module_summaries entry.
        let collector = TelemetryCollector::with_defaults();
        collector.record_module_call("complexity", 5, false);
        collector.record_module_summary_metric("complexity", "health_score", 88.0);
        collector.record_untrusted_data_points(vec![MetricDataPoint {
            name: "chaffra.module.complexity.spoofed_field".to_owned(),
            value: 42.0,
            labels: HashMap::new(),
            timestamp_ms: 0,
        }]);

        let snap = collector.snapshot();
        let metrics = &snap.user_summary.module_summaries["complexity"].metrics;
        assert_eq!(
            metrics.get("health_score"),
            Some(&88.0),
            "trusted per-module metric missing from user summary"
        );
        assert!(
            !metrics.contains_key("spoofed_field"),
            "untrusted spoof leaked into user_summary.module_summaries metrics map"
        );
    }

    #[test]
    fn test_untrusted_runtime_is_never_serialized() {
        // `untrusted_runtime` is `#[serde(skip)]` — it is internal projection
        // metadata (which external names were seen) and must never appear in
        // the on-disk snapshot, under any audience.
        let collector = TelemetryCollector::with_defaults();
        collector.record_untrusted_data_points(vec![MetricDataPoint {
            name: "chaffra.module.plugin.secret_name".to_owned(),
            value: 1.0,
            labels: HashMap::new(),
            timestamp_ms: 0,
        }]);
        let snap = collector
            .snapshot()
            .project_for_audience(TelemetryAudience::OperatorOnly);
        let json = serde_json::to_string(&snap).unwrap();
        assert!(
            !json.contains("untrusted_runtime"),
            "untrusted_runtime field leaked into serialized snapshot"
        );
        assert!(
            !json.contains("secret_name"),
            "untrusted external metric name leaked into serialized snapshot"
        );
    }

    #[test]
    fn test_is_operator_metric_classification() {
        // The full operator set, including the parse-cache family, classifies
        // as operator.
        for name in metric_names::OPERATOR {
            assert!(
                metric_names::is_operator(name),
                "{name} should be operator-only"
            );
        }
        // User-facing metrics — and the collision case: a per-module summary
        // metric whose module id matches an operator name must NOT be misclassified.
        for name in [
            "chaffra.analysis.findings_total",
            "chaffra.analysis.findings_by_severity",
            "chaffra.findings.churn_rate",
            "chaffra.module.dead-code.unused_functions",
            "chaffra.module.error_total.health_score",
        ] {
            assert!(
                !metric_names::is_operator(name),
                "{name} should be user-facing"
            );
        }
    }

    #[test]
    fn test_is_operator_span_all_spans_operator_scoped() {
        let span = SpanData {
            name: "dead-code.analyze".to_owned(),
            trace_id: "t".to_owned(),
            span_id: "s".to_owned(),
            parent_span_id: String::new(),
            start_time_ms: 1,
            end_time_ms: 2,
            attributes: HashMap::new(),
            status: "ok".to_owned(),
        };
        assert!(is_operator_span(&span));
    }

    #[test]
    fn test_collector_thread_safe() {
        let collector = TelemetryCollector::with_defaults();
        let c1 = collector.clone();
        let c2 = collector.clone();

        let t1 = std::thread::spawn(move || {
            c1.record_module_call("mod-a", 10, false);
        });
        let t2 = std::thread::spawn(move || {
            c2.record_module_call("mod-b", 20, false);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let snapshot = collector.snapshot();
        assert_eq!(snapshot.operator_summary.module_call_durations.len(), 2);
    }
}
