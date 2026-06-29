//! Integration tests for the telemetry module (Phase 12).

use std::collections::HashMap;

/// Verify metric registration round-trip.
#[test]
fn test_metric_registration() {
    let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
    let defs = vec![
        chaffra_telemetry::MetricDefinition {
            name: "custom.counter".to_owned(),
            kind: chaffra_telemetry::MetricKind::Counter,
            description: "A custom counter".to_owned(),
            unit: "count".to_owned(),
        },
        chaffra_telemetry::MetricDefinition {
            name: "custom.gauge".to_owned(),
            kind: chaffra_telemetry::MetricKind::Gauge,
            description: "A custom gauge".to_owned(),
            unit: "bytes".to_owned(),
        },
    ];

    collector.register_metrics("test-module", defs).unwrap();

    let snapshot = collector.snapshot();
    assert!(snapshot.definitions.contains_key("custom.counter"));
    assert!(snapshot.definitions.contains_key("custom.gauge"));
    assert_eq!(
        snapshot.definitions["custom.counter"].kind,
        chaffra_telemetry::MetricKind::Counter
    );
}

/// Verify data point recording and snapshot retrieval.
#[test]
fn test_data_point_recording() {
    let collector = chaffra_telemetry::TelemetryCollector::with_defaults();

    // Record several data points.
    for i in 0..5 {
        collector.record_data_point(chaffra_telemetry::MetricDataPoint {
            name: "test.metric".to_owned(),
            value: i as f64,
            labels: {
                let mut m = HashMap::new();
                m.insert("iteration".to_owned(), i.to_string());
                m
            },
            timestamp_ms: 1000 + i,
        });
    }

    let snapshot = collector.snapshot();
    assert_eq!(snapshot.data_points.len(), 5);
    assert!((snapshot.data_points[0].value - 0.0).abs() < f64::EPSILON);
    assert!((snapshot.data_points[4].value - 4.0).abs() < f64::EPSILON);
}

/// Verify JSON file backend produces valid output.
#[test]
fn test_json_file_backend_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("telemetry.json");

    let config = chaffra_telemetry::TelemetryConfig {
        audience: chaffra_telemetry::TelemetryAudience::On,
        backends: vec![chaffra_telemetry::BackendConfig {
            kind: chaffra_telemetry::BackendKind::JsonFile,
            endpoint: None,
            path: Some(path.to_str().unwrap().to_owned()),
            options: HashMap::new(),
        }],
        ..Default::default()
    };

    let collector = chaffra_telemetry::TelemetryCollector::new(config.clone());
    collector.register_core_metrics();
    collector.set_files_total(42);
    collector.record_module_call("dead-code", 100, false);
    collector.record_module_call("complexity", 50, false);

    let mut sev = HashMap::new();
    sev.insert("warning".to_owned(), 5);
    sev.insert("error".to_owned(), 2);
    collector.record_module_findings("dead-code", 7, &sev);

    // R5-Structural: backends accept only `ProjectedSnapshot`, so projection
    // is required at the type level. The audience here is `On`, so the
    // projection is a no-op on data; passing the raw snapshot would not
    // compile.
    let snapshot = collector.snapshot().project_for_audience(config.audience);

    // Flush to JSON file backend.
    let (backends, statuses) = chaffra_telemetry::backends::create_backends(&config.backends);
    assert_eq!(backends.len(), 1);
    assert!(statuses[0].connected);

    backends[0].flush(&snapshot).unwrap();

    // Verify the output file.
    let content = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

    assert_eq!(parsed["user_summary"]["files_total"], 42);
    assert_eq!(parsed["user_summary"]["findings_by_module"]["dead-code"], 7);
    assert!(parsed["data_points"].is_array());
    assert!(!parsed["data_points"].as_array().unwrap().is_empty());
}

/// Verify the telemetry module registers and works via GrpcModuleHost.
#[test]
fn test_telemetry_module_in_grpc_host() {
    use chaffra_core::config::ChaffraConfig;
    use chaffra_core::grpc::GrpcModuleHost;

    let mut host = GrpcModuleHost::new();
    host.register(Box::new(chaffra_telemetry::TelemetryModule::new()))
        .unwrap();

    let modules = host.list();
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].id, "telemetry");

    // Pin `audience = "on"` so this gRPC-host wiring test sees the
    // module's full output surface — both `backend-status` (operator-gated
    // since R4-1) and `metric-summary` (always emitted, payload projected).
    // The default audience is `user-only` (Phase 15a.1 privacy default), under
    // which `backend-status` is intentionally withheld; this test is about
    // gRPC plumbing, not the audience semantics, so we don't want it
    // accidentally drifting whenever the default changes.
    let config = ChaffraConfig::parse("[modules.telemetry]\naudience = \"on\"\n")
        .expect("parse inline config");
    let result = host.analyze("telemetry", &[], &config).unwrap();

    assert!(result.findings.len() >= 2);
    let rule_ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(rule_ids.contains(&"backend-status"));
    assert!(rule_ids.contains(&"metric-summary"));
}

/// Verify explain works for telemetry rules.
#[test]
fn test_telemetry_explain_via_host() {
    use chaffra_core::grpc::GrpcModuleHost;

    let mut host = GrpcModuleHost::new();
    host.register(Box::new(chaffra_telemetry::TelemetryModule::new()))
        .unwrap();

    let explanation = host.explain("telemetry:backend-status").unwrap();
    assert_eq!(explanation.rule_id, "backend-status");
    assert!(explanation.description.contains("connectivity"));

    let explanation = host.explain("telemetry:metric-summary").unwrap();
    assert_eq!(explanation.rule_id, "metric-summary");
}

/// Verify backend status reporting.
#[test]
fn test_backend_status_reporting() {
    let config = chaffra_telemetry::TelemetryConfig::default();
    let (backends, statuses) = chaffra_telemetry::backends::create_backends(&config.backends);

    assert_eq!(backends.len(), 1);
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].name, "json-file");
    assert!(statuses[0].connected);
}

/// Verify the collector handles concurrent writes safely.
#[test]
fn test_concurrent_metric_recording() {
    let collector = chaffra_telemetry::TelemetryCollector::with_defaults();
    let mut handles = vec![];

    for i in 0..10 {
        let c = collector.clone();
        handles.push(std::thread::spawn(move || {
            c.record_module_call(&format!("module-{i}"), (i * 10) as u64, i % 3 == 0);
            c.record_data_point(chaffra_telemetry::MetricDataPoint {
                name: format!("test.thread.{i}"),
                value: i as f64,
                labels: HashMap::new(),
                timestamp_ms: 1000,
            });
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let snapshot = collector.snapshot();
    assert_eq!(snapshot.operator_summary.module_call_durations.len(), 10);
    // Each module_call records a data_point + explicit data_point = 2 per thread
    assert!(snapshot.data_points.len() >= 20);
}

/// Verify Prometheus exposition format output.
#[test]
fn test_prometheus_exposition_format() {
    let config = chaffra_telemetry::TelemetryConfig {
        audience: chaffra_telemetry::TelemetryAudience::On,
        backends: vec![chaffra_telemetry::BackendConfig {
            kind: chaffra_telemetry::BackendKind::Prometheus,
            endpoint: None,
            path: None,
            options: HashMap::new(),
        }],
        ..Default::default()
    };

    let collector = chaffra_telemetry::TelemetryCollector::new(config.clone());
    collector.register_core_metrics();
    collector.record_module_call("test", 42, false);
    // R5-Structural: backends accept only `ProjectedSnapshot` — projection
    // required at the type level.
    let snapshot = collector.snapshot().project_for_audience(config.audience);

    let (backends, _) = chaffra_telemetry::backends::create_backends(&config.backends);
    let output = backends[0].inspect(&snapshot).unwrap();

    assert!(output.contains("# HELP"));
    assert!(output.contains("# TYPE"));
    assert!(output.contains("chaffra_module_call_duration_ms"));
}

/// Verify OTLP payload generation.
#[test]
fn test_otlp_payload_format() {
    let config = chaffra_telemetry::TelemetryConfig {
        audience: chaffra_telemetry::TelemetryAudience::On,
        backends: vec![chaffra_telemetry::BackendConfig {
            kind: chaffra_telemetry::BackendKind::Otlp,
            endpoint: Some("http://localhost:4317".to_owned()),
            path: None,
            options: HashMap::new(),
        }],
        ..Default::default()
    };

    let collector = chaffra_telemetry::TelemetryCollector::new(config.clone());
    collector.register_core_metrics();
    collector.record_module_call("security", 100, false);
    // R5-Structural: backends accept only `ProjectedSnapshot` — projection
    // required at the type level.
    let snapshot = collector.snapshot().project_for_audience(config.audience);

    let (backends, _) = chaffra_telemetry::backends::create_backends(&config.backends);
    let output = backends[0].inspect(&snapshot).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();

    assert!(parsed["resourceMetrics"].is_array());
    let scope_metrics = &parsed["resourceMetrics"][0]["scopeMetrics"][0];
    assert_eq!(scope_metrics["scope"]["name"], "chaffra-telemetry");
}

/// Verify StatsD line format.
#[test]
fn test_statsd_line_format() {
    let config = chaffra_telemetry::TelemetryConfig {
        audience: chaffra_telemetry::TelemetryAudience::On,
        backends: vec![chaffra_telemetry::BackendConfig {
            kind: chaffra_telemetry::BackendKind::Statsd,
            endpoint: Some("127.0.0.1:8125".to_owned()),
            path: None,
            options: HashMap::new(),
        }],
        ..Default::default()
    };

    let collector = chaffra_telemetry::TelemetryCollector::new(config.clone());
    collector.register_core_metrics();
    collector.record_module_call("hotspot", 30, false);
    // R5-Structural: backends accept only `ProjectedSnapshot` — projection
    // required at the type level.
    let snapshot = collector.snapshot().project_for_audience(config.audience);

    let (backends, _) = chaffra_telemetry::backends::create_backends(&config.backends);
    let output = backends[0].inspect(&snapshot).unwrap();

    // StatsD format: metric_name:value|type|#tags
    assert!(output.contains("chaffra.module.call_duration_ms:30|"));
}

/// Verify audience filtering works.
#[test]
fn test_audience_filtering() {
    // User-only: operator should be disabled.
    let audience = chaffra_telemetry::TelemetryAudience::UserOnly;
    assert!(audience.user_enabled());
    assert!(!audience.operator_enabled());

    // Operator-only: user should be disabled.
    let audience = chaffra_telemetry::TelemetryAudience::OperatorOnly;
    assert!(!audience.user_enabled());
    assert!(audience.operator_enabled());

    // Off: both disabled.
    let audience = chaffra_telemetry::TelemetryAudience::Off;
    assert!(!audience.user_enabled());
    assert!(!audience.operator_enabled());
}
