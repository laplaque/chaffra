//! Docker Compose security analysis.
//!
//! Rules:
//! - `compose-privileged`: privileged container
//! - `compose-host-network`: host network mode
//! - `compose-host-mount`: sensitive host path mount

use chaffra_core::diagnostic::{Finding, Location, Severity};
use chaffra_core::error::Result;
use serde_yaml::Value;
use std::collections::HashMap;

/// Sensitive host paths that should not be mounted.
const SENSITIVE_PATHS: &[&str] = &[
    "/",
    "/etc",
    "/var/run/docker.sock",
    "/root",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
];

/// Analyze a Docker Compose file.
pub fn analyze(path: &str, content: &str, findings: &mut Vec<Finding>) -> Result<()> {
    let doc: Value = serde_yaml::from_str(content)
        .map_err(|e| chaffra_core::error::ChaffraError::Parse(format!("YAML parse error: {e}")))?;

    let services = match doc.get("services") {
        Some(Value::Mapping(m)) => m,
        _ => return Ok(()), // No services section
    };

    for (svc_name, svc_def) in services {
        let name = match svc_name {
            Value::String(s) => s.as_str(),
            _ => "unknown",
        };

        check_privileged(path, content, svc_def, findings, name);
        check_host_network(path, content, svc_def, findings, name);
        check_host_mounts(path, content, svc_def, findings, name);
    }

    Ok(())
}

/// Check for privileged mode.
fn check_privileged(
    path: &str,
    content: &str,
    svc: &Value,
    findings: &mut Vec<Finding>,
    name: &str,
) {
    if let Some(Value::Bool(true)) = svc.get("privileged") {
        let line = find_line_for_service(content, name, "privileged");
        findings.push(Finding {
            rule_id: "compose-privileged".to_owned(),
            message: format!("service `{name}` runs in privileged mode"),
            severity: Severity::Error,
            location: Location {
                file: path.to_owned(),
                start_line: line,
                end_line: line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 1.0,
            actions: vec![],
            metadata: HashMap::new(),
        });
    }
}

/// Check for host network mode.
fn check_host_network(
    path: &str,
    content: &str,
    svc: &Value,
    findings: &mut Vec<Finding>,
    name: &str,
) {
    if let Some(Value::String(mode)) = svc.get("network_mode") {
        if mode == "host" {
            let line = find_line_for_service(content, name, "network_mode");
            findings.push(Finding {
                rule_id: "compose-host-network".to_owned(),
                message: format!("service `{name}` uses host network mode"),
                severity: Severity::Warning,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    }
}

/// Check for sensitive host path mounts.
fn check_host_mounts(
    path: &str,
    content: &str,
    svc: &Value,
    findings: &mut Vec<Finding>,
    name: &str,
) {
    let volumes = match svc.get("volumes") {
        Some(Value::Sequence(seq)) => seq,
        _ => return,
    };

    for vol in volumes {
        let mount_str = match vol {
            Value::String(s) => s.clone(),
            Value::Mapping(m) => {
                // Long syntax: { type: bind, source: /host/path, target: /container/path }
                match (
                    m.get(Value::String("type".to_owned())),
                    m.get(Value::String("source".to_owned())),
                ) {
                    (Some(Value::String(t)), Some(Value::String(src))) if t == "bind" => {
                        format!("{src}:/target")
                    }
                    _ => continue,
                }
            }
            _ => continue,
        };

        // Parse short syntax: host_path:container_path[:options]
        let host_path = mount_str.split(':').next().unwrap_or("");
        if is_sensitive_path(host_path) {
            let line = find_line_for_service(content, name, host_path);
            findings.push(Finding {
                rule_id: "compose-host-mount".to_owned(),
                message: format!("service `{name}` mounts sensitive host path `{host_path}`"),
                severity: Severity::Error,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
    }
}

fn is_sensitive_path(host_path: &str) -> bool {
    let normalized = host_path.trim_end_matches('/');
    SENSITIVE_PATHS.iter().any(|sensitive| {
        let s = sensitive.trim_end_matches('/');
        normalized == s || (s.is_empty() && normalized.is_empty())
    })
}

fn find_line_for_service(content: &str, _service_name: &str, keyword: &str) -> u32 {
    if let Some(pos) = content.find(keyword) {
        content[..pos].matches('\n').count() as u32 + 1
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privileged_container() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    privileged: true
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "compose-privileged"),
            "should detect privileged mode: {findings:?}"
        );
    }

    #[test]
    fn test_not_privileged_ok() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    privileged: false
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().all(|f| f.rule_id != "compose-privileged"),
            "privileged: false should not be flagged"
        );
    }

    #[test]
    fn test_host_network() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    network_mode: host
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "compose-host-network"),
            "should detect host network: {findings:?}"
        );
    }

    #[test]
    fn test_bridge_network_ok() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    network_mode: bridge
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().all(|f| f.rule_id != "compose-host-network"),
            "bridge network should not be flagged"
        );
    }

    #[test]
    fn test_docker_socket_mount() {
        let yaml = r#"
services:
  dind:
    image: docker:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "compose-host-mount"),
            "should detect Docker socket mount: {findings:?}"
        );
    }

    #[test]
    fn test_root_mount() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - /:/host
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "compose-host-mount"),
            "should detect root mount: {findings:?}"
        );
    }

    #[test]
    fn test_etc_mount() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - /etc:/etc:ro
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "compose-host-mount"),
            "should detect /etc mount: {findings:?}"
        );
    }

    #[test]
    fn test_safe_volume_ok() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - ./data:/app/data
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().all(|f| f.rule_id != "compose-host-mount"),
            "relative path should not be flagged"
        );
    }

    #[test]
    fn test_named_volume_ok() {
        let yaml = r#"
services:
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().all(|f| f.rule_id != "compose-host-mount"),
            "named volume should not be flagged"
        );
    }

    #[test]
    fn test_long_syntax_bind_mount() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    volumes:
      - type: bind
        source: /etc
        target: /host-etc
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "compose-host-mount"),
            "long syntax bind mount should be detected: {findings:?}"
        );
    }

    #[test]
    fn test_no_services_ok() {
        let yaml = "version: '3.8'\n";
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_multiple_issues() {
        let yaml = r#"
services:
  app:
    image: myapp:latest
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"#;
        let mut findings = Vec::new();
        analyze("docker-compose.yml", yaml, &mut findings).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "compose-privileged"));
        assert!(findings.iter().any(|f| f.rule_id == "compose-host-network"));
        assert!(findings.iter().any(|f| f.rule_id == "compose-host-mount"));
    }

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path("/"));
        assert!(is_sensitive_path("/etc"));
        assert!(is_sensitive_path("/var/run/docker.sock"));
        assert!(is_sensitive_path("/root"));
        assert!(is_sensitive_path("/proc"));
        assert!(!is_sensitive_path("./data"));
        assert!(!is_sensitive_path("/app/data"));
        assert!(!is_sensitive_path("pgdata"));
    }
}
