use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DashboardDatasource {
    Prometheus,
    Otlp,
}

impl DashboardDatasource {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "prometheus" | "prom" => Some(Self::Prometheus),
            "otlp" | "otel" | "opentelemetry" => Some(Self::Otlp),
            _ => None,
        }
    }

    fn datasource_type(&self) -> &str {
        match self {
            Self::Prometheus => "prometheus",
            Self::Otlp => "prometheus",
        }
    }

    fn datasource_uid(&self) -> &str {
        match self {
            Self::Prometheus => "${DS_PROMETHEUS}",
            Self::Otlp => "${DS_OTLP}",
        }
    }
}

pub fn generate_dashboard(datasource: DashboardDatasource) -> Value {
    let ds = json!({ "type": datasource.datasource_type(), "uid": datasource.datasource_uid() });

    let templating = json!({
        "list": [
            {
                "name": "DS_PROMETHEUS",
                "type": "datasource",
                "query": datasource.datasource_type(),
                "current": {},
                "hide": if datasource == DashboardDatasource::Prometheus { 0 } else { 2 },
            },
            {
                "name": "DS_OTLP",
                "type": "datasource",
                "query": datasource.datasource_type(),
                "current": {},
                "hide": if datasource == DashboardDatasource::Otlp { 0 } else { 2 },
            },
            template_var("tenant_id", "chaffra_health_score", "tenant_id"),
            template_var("environment", "chaffra_health_score", "environment"),
            template_var("project", "chaffra_health_score", "project"),
        ]
    });

    let panels = vec![
        row_panel(0, "Overview", 0),
        health_score_trend_panel(1, &ds, 1),
        finding_count_by_module_panel(2, &ds, 5),
        finding_churn_panel(3, &ds, 13),
        row_panel(4, "Per-module Detail", 21),
        module_call_duration_panel(5, &ds, 22),
        module_finding_breakdown_panel(6, &ds, 30),
        row_panel(7, "Operational", 38),
        error_rate_panel(8, &ds, 39),
        startup_time_panel(9, &ds, 47),
    ];

    json!({
        "__inputs": [
            {
                "name": datasource.datasource_uid().trim_start_matches('$').trim_matches(|c| c == '{' || c == '}'),
                "label": if datasource == DashboardDatasource::Prometheus { "Prometheus" } else { "OTLP" },
                "type": "datasource",
                "pluginId": datasource.datasource_type(),
            }
        ],
        "annotations": { "list": [] },
        "editable": true,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 1,
        "id": Value::Null,
        "links": [],
        "panels": panels,
        "schemaVersion": 39,
        "tags": ["chaffra", "codebase-intelligence"],
        "templating": templating,
        "time": { "from": "now-7d", "to": "now" },
        "timepicker": {},
        "timezone": "browser",
        "title": "Chaffra Codebase Intelligence",
        "uid": Value::Null,
        "version": 1,
        "refresh": "5m",
    })
}

fn template_var(name: &str, metric: &str, label: &str) -> Value {
    json!({
        "name": name,
        "type": "query",
        "query": format!("label_values({metric}, {label})"),
        "refresh": 2,
        "multi": false,
        "includeAll": true,
        "allValue": ".*",
        "current": { "text": "All", "value": "$__all" },
    })
}

fn row_panel(id: u32, title: &str, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "row",
        "title": title,
        "collapsed": false,
        "gridPos": { "h": 1, "w": 24, "x": 0, "y": grid_y },
        "panels": [],
    })
}

fn health_score_trend_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "timeseries",
        "title": "Health Score Trend",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": grid_y },
        "fieldConfig": {
            "defaults": {
                "min": 0, "max": 100,
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        { "color": "red", "value": null },
                        { "color": "orange", "value": 40 },
                        { "color": "yellow", "value": 60 },
                        { "color": "green", "value": 80 },
                    ]
                },
                "unit": "percent",
            },
            "overrides": [],
        },
        "targets": [{
            "expr": "chaffra_health_score{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
            "legendFormat": "{{project}}",
            "refId": "A",
        }],
    })
}

fn finding_count_by_module_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "barchart",
        "title": "Finding Count by Module",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": grid_y },
        "fieldConfig": { "defaults": { "unit": "short" }, "overrides": [] },
        "targets": [{
            "expr": "chaffra_module_finding_count{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
            "legendFormat": "{{module}}",
            "refId": "A",
        }],
        "options": {
            "orientation": "horizontal",
            "stacking": "none",
        },
    })
}

fn finding_churn_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "timeseries",
        "title": "Finding Churn",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 24, "x": 0, "y": grid_y },
        "fieldConfig": {
            "defaults": { "unit": "short" },
            "overrides": [
                { "matcher": { "id": "byName", "options": "New" }, "properties": [{ "id": "color", "value": { "fixedColor": "red", "mode": "fixed" } }] },
                { "matcher": { "id": "byName", "options": "Resolved" }, "properties": [{ "id": "color", "value": { "fixedColor": "green", "mode": "fixed" } }] },
                { "matcher": { "id": "byName", "options": "Unchanged" }, "properties": [{ "id": "color", "value": { "fixedColor": "blue", "mode": "fixed" } }] },
            ],
        },
        "targets": [
            { "expr": "chaffra_finding_churn_new{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}", "legendFormat": "New", "refId": "A" },
            { "expr": "chaffra_finding_churn_resolved{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}", "legendFormat": "Resolved", "refId": "B" },
            { "expr": "chaffra_finding_churn_unchanged{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}", "legendFormat": "Unchanged", "refId": "C" },
        ],
    })
}

fn module_call_duration_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "timeseries",
        "title": "Module Call Duration",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": grid_y },
        "fieldConfig": { "defaults": { "unit": "ms" }, "overrides": [] },
        "targets": [{
            "expr": "chaffra_module_call_duration_ms{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
            "legendFormat": "{{module}}",
            "refId": "A",
        }],
    })
}

fn module_finding_breakdown_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "piechart",
        "title": "Findings by Severity",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": grid_y },
        "fieldConfig": {
            "defaults": { "unit": "short" },
            "overrides": [
                { "matcher": { "id": "byName", "options": "error" }, "properties": [{ "id": "color", "value": { "fixedColor": "red", "mode": "fixed" } }] },
                { "matcher": { "id": "byName", "options": "warning" }, "properties": [{ "id": "color", "value": { "fixedColor": "orange", "mode": "fixed" } }] },
                { "matcher": { "id": "byName", "options": "info" }, "properties": [{ "id": "color", "value": { "fixedColor": "blue", "mode": "fixed" } }] },
            ],
        },
        "targets": [{
            "expr": "chaffra_findings_by_severity{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
            "legendFormat": "{{severity}}",
            "refId": "A",
        }],
    })
}

fn error_rate_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "timeseries",
        "title": "Error Rates",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 12, "x": 0, "y": grid_y },
        "fieldConfig": {
            "defaults": {
                "unit": "short",
                "thresholds": {
                    "mode": "absolute",
                    "steps": [
                        { "color": "green", "value": null },
                        { "color": "red", "value": 1 },
                    ]
                },
            },
            "overrides": [],
        },
        "targets": [{
            "expr": "chaffra_module_error_count{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
            "legendFormat": "{{module}}",
            "refId": "A",
        }],
    })
}

fn startup_time_panel(id: u32, ds: &Value, grid_y: u32) -> Value {
    json!({
        "id": id,
        "type": "timeseries",
        "title": "Startup Time",
        "datasource": ds,
        "gridPos": { "h": 8, "w": 12, "x": 12, "y": grid_y },
        "fieldConfig": { "defaults": { "unit": "ms" }, "overrides": [] },
        "targets": [
            {
                "expr": "chaffra_startup_total_duration_ms{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
                "legendFormat": "Total",
                "refId": "A",
            },
            {
                "expr": "chaffra_module_startup_duration_ms{tenant_id=~\"$tenant_id\",environment=~\"$environment\",project=~\"$project\"}",
                "legendFormat": "{{module}}",
                "refId": "B",
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_prometheus_dashboard() {
        let dashboard = generate_dashboard(DashboardDatasource::Prometheus);
        assert_eq!(dashboard["title"], "Chaffra Codebase Intelligence");
        assert_eq!(dashboard["schemaVersion"], 39);

        let panels = dashboard["panels"].as_array().unwrap();
        assert_eq!(panels.len(), 10);

        let rows: Vec<_> = panels.iter().filter(|p| p["type"] == "row").collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["title"], "Overview");
        assert_eq!(rows[1]["title"], "Per-module Detail");
        assert_eq!(rows[2]["title"], "Operational");

        let template_vars = dashboard["templating"]["list"].as_array().unwrap();
        let var_names: Vec<&str> = template_vars
            .iter()
            .filter_map(|v| v["name"].as_str())
            .collect();
        assert!(var_names.contains(&"tenant_id"));
        assert!(var_names.contains(&"environment"));
        assert!(var_names.contains(&"project"));
    }

    #[test]
    fn test_generate_otlp_dashboard() {
        let dashboard = generate_dashboard(DashboardDatasource::Otlp);
        assert_eq!(dashboard["title"], "Chaffra Codebase Intelligence");

        let inputs = dashboard["__inputs"].as_array().unwrap();
        assert_eq!(inputs[0]["name"], "DS_OTLP");
    }

    #[test]
    fn test_dashboard_has_required_panels() {
        let dashboard = generate_dashboard(DashboardDatasource::Prometheus);
        let panels = dashboard["panels"].as_array().unwrap();

        let titles: Vec<&str> = panels.iter().filter_map(|p| p["title"].as_str()).collect();
        assert!(titles.contains(&"Health Score Trend"));
        assert!(titles.contains(&"Finding Count by Module"));
        assert!(titles.contains(&"Finding Churn"));
        assert!(titles.contains(&"Module Call Duration"));
        assert!(titles.contains(&"Error Rates"));
        assert!(titles.contains(&"Startup Time"));
    }

    #[test]
    fn test_datasource_from_str() {
        assert_eq!(
            DashboardDatasource::from_str_loose("prometheus"),
            Some(DashboardDatasource::Prometheus)
        );
        assert_eq!(
            DashboardDatasource::from_str_loose("OTLP"),
            Some(DashboardDatasource::Otlp)
        );
        assert_eq!(DashboardDatasource::from_str_loose("unknown"), None);
    }

    #[test]
    fn test_dashboard_json_is_valid() {
        let dashboard = generate_dashboard(DashboardDatasource::Prometheus);
        let json_str = serde_json::to_string_pretty(&dashboard).unwrap();
        let reparsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(dashboard, reparsed);
    }
}
