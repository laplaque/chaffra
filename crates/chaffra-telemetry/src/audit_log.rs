use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::path::Path;

pub const AUDIT_LOG_FILE: &str = ".chaffra-telemetry-audit.log";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    TelemetryEnabled {
        timestamp_ms: u64,
        user: Option<String>,
        audience: String,
    },
    TelemetryDisabled {
        timestamp_ms: u64,
        user: Option<String>,
    },
    BackendAdded {
        timestamp_ms: u64,
        user: Option<String>,
        backend_kind: String,
        backend_endpoint: Option<String>,
    },
    BackendRemoved {
        timestamp_ms: u64,
        user: Option<String>,
        backend_kind: String,
    },
    BackendModified {
        timestamp_ms: u64,
        user: Option<String>,
        backend_kind: String,
        field: String,
        old_value: String,
        new_value: String,
    },
    TenantIdChanged {
        timestamp_ms: u64,
        user: Option<String>,
        old_value: Option<String>,
        new_value: String,
    },
    PathModeChanged {
        timestamp_ms: u64,
        user: Option<String>,
        old_value: String,
        new_value: String,
    },
    SamplingRateChanged {
        timestamp_ms: u64,
        user: Option<String>,
        old_value: f64,
        new_value: f64,
    },
}

impl AuditEvent {
    pub fn timestamp_ms(&self) -> u64 {
        match self {
            Self::TelemetryEnabled { timestamp_ms, .. }
            | Self::TelemetryDisabled { timestamp_ms, .. }
            | Self::BackendAdded { timestamp_ms, .. }
            | Self::BackendRemoved { timestamp_ms, .. }
            | Self::BackendModified { timestamp_ms, .. }
            | Self::TenantIdChanged { timestamp_ms, .. }
            | Self::PathModeChanged { timestamp_ms, .. }
            | Self::SamplingRateChanged { timestamp_ms, .. } => *timestamp_ms,
        }
    }

    pub fn event_type(&self) -> &str {
        match self {
            Self::TelemetryEnabled { .. } => "telemetry_enabled",
            Self::TelemetryDisabled { .. } => "telemetry_disabled",
            Self::BackendAdded { .. } => "backend_added",
            Self::BackendRemoved { .. } => "backend_removed",
            Self::BackendModified { .. } => "backend_modified",
            Self::TenantIdChanged { .. } => "tenant_id_changed",
            Self::PathModeChanged { .. } => "path_mode_changed",
            Self::SamplingRateChanged { .. } => "sampling_rate_changed",
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn log_telemetry_enabled(audience: &str, user: Option<String>) {
    let event = AuditEvent::TelemetryEnabled {
        timestamp_ms: now_ms(),
        user,
        audience: audience.to_owned(),
    };
    append_event(&event, Path::new(AUDIT_LOG_FILE));
}

pub fn log_telemetry_disabled(user: Option<String>) {
    let event = AuditEvent::TelemetryDisabled {
        timestamp_ms: now_ms(),
        user,
    };
    append_event(&event, Path::new(AUDIT_LOG_FILE));
}

pub fn log_backend_added(kind: &str, endpoint: Option<String>, user: Option<String>) {
    let event = AuditEvent::BackendAdded {
        timestamp_ms: now_ms(),
        user,
        backend_kind: kind.to_owned(),
        backend_endpoint: endpoint,
    };
    append_event(&event, Path::new(AUDIT_LOG_FILE));
}

pub fn log_backend_removed(kind: &str, user: Option<String>) {
    let event = AuditEvent::BackendRemoved {
        timestamp_ms: now_ms(),
        user,
        backend_kind: kind.to_owned(),
    };
    append_event(&event, Path::new(AUDIT_LOG_FILE));
}

pub fn log_sampling_rate_changed(old: f64, new: f64, user: Option<String>) {
    let event = AuditEvent::SamplingRateChanged {
        timestamp_ms: now_ms(),
        user,
        old_value: old,
        new_value: new,
    };
    append_event(&event, Path::new(AUDIT_LOG_FILE));
}

pub fn log_tenant_id_changed(old: Option<String>, new: &str, user: Option<String>) {
    let event = AuditEvent::TenantIdChanged {
        timestamp_ms: now_ms(),
        user,
        old_value: old,
        new_value: new.to_owned(),
    };
    append_event(&event, Path::new(AUDIT_LOG_FILE));
}

pub fn append_event(event: &AuditEvent, path: &Path) {
    let line = match serde_json::to_string(event) {
        Ok(l) => l,
        Err(_) => return,
    };
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(f) => f,
        Err(_) => return,
    };
    let _ = writeln!(file, "{line}");
}

pub fn read_log(path: &Path) -> Vec<AuditEvent> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let reader = std::io::BufReader::new(file);
    reader
        .lines()
        .map_while(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<AuditEvent>(&line).ok())
        .collect()
}

pub fn format_log_display(events: &[AuditEvent]) -> String {
    if events.is_empty() {
        return "No telemetry audit events recorded.\n".to_owned();
    }

    let mut output = String::from("Telemetry Audit Log\n");
    output.push_str(&"=".repeat(60));
    output.push('\n');

    for event in events {
        let ts = event.timestamp_ms();
        let kind = event.event_type();
        output.push_str(&format!("[{ts}] {kind}"));
        match event {
            AuditEvent::TelemetryEnabled { audience, user, .. } => {
                output.push_str(&format!(" audience={audience}"));
                if let Some(u) = user {
                    output.push_str(&format!(" user={u}"));
                }
            }
            AuditEvent::TelemetryDisabled { user, .. } => {
                if let Some(u) = user {
                    output.push_str(&format!(" user={u}"));
                }
            }
            AuditEvent::BackendAdded {
                backend_kind,
                backend_endpoint,
                ..
            } => {
                output.push_str(&format!(" kind={backend_kind}"));
                if let Some(ep) = backend_endpoint {
                    output.push_str(&format!(" endpoint={ep}"));
                }
            }
            AuditEvent::BackendRemoved { backend_kind, .. } => {
                output.push_str(&format!(" kind={backend_kind}"));
            }
            AuditEvent::BackendModified {
                backend_kind,
                field,
                old_value,
                new_value,
                ..
            } => {
                output.push_str(&format!(
                    " kind={backend_kind} {field}: {old_value} -> {new_value}"
                ));
            }
            AuditEvent::TenantIdChanged {
                old_value,
                new_value,
                ..
            } => {
                let old = old_value.as_deref().unwrap_or("(none)");
                output.push_str(&format!(" {old} -> {new_value}"));
            }
            AuditEvent::PathModeChanged {
                old_value,
                new_value,
                ..
            } => {
                output.push_str(&format!(" {old_value} -> {new_value}"));
            }
            AuditEvent::SamplingRateChanged {
                old_value,
                new_value,
                ..
            } => {
                output.push_str(&format!(" {old_value} -> {new_value}"));
            }
        }
        output.push('\n');
    }
    output
}

pub fn export_for_gdpr(events: &[AuditEvent]) -> String {
    serde_json::to_string_pretty(events).unwrap_or_else(|_| "[]".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_read_events() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path = dir.path().join(AUDIT_LOG_FILE);

        let event1 = AuditEvent::TelemetryEnabled {
            timestamp_ms: 1000,
            user: Some("test-user".to_owned()),
            audience: "on".to_owned(),
        };
        let event2 = AuditEvent::BackendAdded {
            timestamp_ms: 2000,
            user: None,
            backend_kind: "json-file".to_owned(),
            backend_endpoint: None,
        };

        append_event(&event1, &log_path);
        append_event(&event2, &log_path);

        let events = read_log(&log_path);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], event1);
        assert_eq!(events[1], event2);
    }

    #[test]
    fn test_read_nonexistent_log() {
        let events = read_log(Path::new("/nonexistent/path"));
        assert!(events.is_empty());
    }

    #[test]
    fn test_format_empty_log() {
        let output = format_log_display(&[]);
        assert!(output.contains("No telemetry audit events"));
    }

    #[test]
    fn test_format_log_display() {
        let events = vec![
            AuditEvent::TelemetryEnabled {
                timestamp_ms: 1000,
                user: Some("admin".to_owned()),
                audience: "on".to_owned(),
            },
            AuditEvent::SamplingRateChanged {
                timestamp_ms: 2000,
                user: None,
                old_value: 1.0,
                new_value: 0.5,
            },
        ];

        let output = format_log_display(&events);
        assert!(output.contains("telemetry_enabled"));
        assert!(output.contains("audience=on"));
        assert!(output.contains("user=admin"));
        assert!(output.contains("sampling_rate_changed"));
        assert!(output.contains("1 -> 0.5"));
    }

    #[test]
    fn test_gdpr_export() {
        let events = vec![AuditEvent::TelemetryDisabled {
            timestamp_ms: 3000,
            user: Some("gdpr-requestor".to_owned()),
        }];

        let exported = export_for_gdpr(&events);
        let parsed: Vec<AuditEvent> = serde_json::from_str(&exported).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].event_type(), "telemetry_disabled");
    }

    #[test]
    fn test_event_type_names() {
        let event = AuditEvent::BackendRemoved {
            timestamp_ms: 0,
            user: None,
            backend_kind: "stderr".to_owned(),
        };
        assert_eq!(event.event_type(), "backend_removed");
        assert_eq!(event.timestamp_ms(), 0);
    }

    #[test]
    fn test_roundtrip_all_event_types() {
        let dir = tempfile::TempDir::new().unwrap();
        let log_path = dir.path().join("test-audit.log");

        let events = vec![
            AuditEvent::TelemetryEnabled {
                timestamp_ms: 1,
                user: None,
                audience: "on".to_owned(),
            },
            AuditEvent::TelemetryDisabled {
                timestamp_ms: 2,
                user: None,
            },
            AuditEvent::BackendAdded {
                timestamp_ms: 3,
                user: None,
                backend_kind: "otlp".to_owned(),
                backend_endpoint: Some("http://localhost:4317".to_owned()),
            },
            AuditEvent::BackendRemoved {
                timestamp_ms: 4,
                user: None,
                backend_kind: "otlp".to_owned(),
            },
            AuditEvent::BackendModified {
                timestamp_ms: 5,
                user: None,
                backend_kind: "otlp".to_owned(),
                field: "endpoint".to_owned(),
                old_value: "http://old:4317".to_owned(),
                new_value: "http://new:4317".to_owned(),
            },
            AuditEvent::TenantIdChanged {
                timestamp_ms: 6,
                user: None,
                old_value: None,
                new_value: "tenant-1".to_owned(),
            },
            AuditEvent::PathModeChanged {
                timestamp_ms: 7,
                user: None,
                old_value: "relative".to_owned(),
                new_value: "absolute".to_owned(),
            },
            AuditEvent::SamplingRateChanged {
                timestamp_ms: 8,
                user: None,
                old_value: 1.0,
                new_value: 0.1,
            },
        ];

        for e in &events {
            append_event(e, &log_path);
        }

        let loaded = read_log(&log_path);
        assert_eq!(loaded, events);
    }
}
