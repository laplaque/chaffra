//! systemd service unit security analysis.
//!
//! Rules:
//! - `systemd-root-execution`: service runs as root (no User= or User=root)
//! - `systemd-missing-hardening`: missing recommended sandboxing directives

use chaffra_core::diagnostic::{Finding, Location, Severity};
use std::collections::HashMap;

/// Recommended hardening directives.
const HARDENING_DIRECTIVES: &[&str] = &[
    "ProtectSystem",
    "ProtectHome",
    "NoNewPrivileges",
    "PrivateTmp",
];

/// Analyze a systemd .service unit file.
pub fn analyze(path: &str, content: &str, findings: &mut Vec<Finding>) {
    let directives = parse_ini(content);

    check_root_execution(path, content, &directives, findings);
    check_hardening(path, content, &directives, findings);
}

/// Parse an INI-style systemd unit file into (key, value) pairs.
fn parse_ini(content: &str) -> Vec<(String, String, u32)> {
    let mut result = Vec::new();

    for (i, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Skip comments and section headers
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with(';')
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            continue;
        }

        // Parse key=value
        if let Some((key, value)) = trimmed.split_once('=') {
            result.push((
                key.trim().to_string(),
                value.trim().to_string(),
                (i + 1) as u32,
            ));
        }
    }

    result
}

/// Check if the service runs as root.
fn check_root_execution(
    path: &str,
    content: &str,
    directives: &[(String, String, u32)],
    findings: &mut Vec<Finding>,
) {
    // Check if there's a [Service] section
    if !content.contains("[Service]") {
        return;
    }

    let user_directive = directives.iter().find(|(k, _, _)| k == "User");

    match user_directive {
        None => {
            // No User= directive -> runs as root by default
            let line = find_line_number(content, "[Service]");
            findings.push(Finding {
                rule_id: "systemd-root-execution".to_owned(),
                message: "service does not specify User= directive and will run as root".to_owned(),
                severity: Severity::Warning,
                location: Location {
                    file: path.to_owned(),
                    start_line: line,
                    end_line: line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 0.95,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
        Some((_, value, line)) if value == "root" || value == "0" => {
            findings.push(Finding {
                rule_id: "systemd-root-execution".to_owned(),
                message: format!("service explicitly runs as `{value}`"),
                severity: Severity::Warning,
                location: Location {
                    file: path.to_owned(),
                    start_line: *line,
                    end_line: *line,
                    start_column: 0,
                    end_column: 0,
                },
                confidence: 1.0,
                actions: vec![],
                metadata: HashMap::new(),
            });
        }
        _ => {} // Has a non-root User, OK
    }
}

/// Check for missing hardening directives.
fn check_hardening(
    path: &str,
    content: &str,
    directives: &[(String, String, u32)],
    findings: &mut Vec<Finding>,
) {
    if !content.contains("[Service]") {
        return;
    }

    let present_keys: Vec<&str> = directives.iter().map(|(k, _, _)| k.as_str()).collect();

    let missing: Vec<&str> = HARDENING_DIRECTIVES
        .iter()
        .filter(|d| !present_keys.contains(*d))
        .copied()
        .collect();

    if !missing.is_empty() {
        let line = find_line_number(content, "[Service]");
        findings.push(Finding {
            rule_id: "systemd-missing-hardening".to_owned(),
            message: format!("missing hardening directives: {}", missing.join(", ")),
            severity: Severity::Info,
            location: Location {
                file: path.to_owned(),
                start_line: line,
                end_line: line,
                start_column: 0,
                end_column: 0,
            },
            confidence: 0.8,
            actions: vec![],
            metadata: HashMap::new(),
        });
    }
}

fn find_line_number(content: &str, needle: &str) -> u32 {
    if let Some(pos) = content.find(needle) {
        content[..pos].matches('\n').count() as u32 + 1
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_execution_no_user() {
        let content = "[Unit]\nDescription=My Service\n\n[Service]\nExecStart=/usr/bin/myapp\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "systemd-root-execution"),
            "should detect missing User: {findings:?}"
        );
    }

    #[test]
    fn test_root_execution_explicit_root() {
        let content =
            "[Unit]\nDescription=My Service\n\n[Service]\nUser=root\nExecStart=/usr/bin/myapp\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "systemd-root-execution" && f.message.contains("root")),
            "should detect User=root: {findings:?}"
        );
    }

    #[test]
    fn test_root_execution_uid_zero() {
        let content =
            "[Unit]\nDescription=My Service\n\n[Service]\nUser=0\nExecStart=/usr/bin/myapp\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "systemd-root-execution"),
            "should detect User=0"
        );
    }

    #[test]
    fn test_non_root_user_ok() {
        let content =
            "[Unit]\nDescription=My Service\n\n[Service]\nUser=myapp\nExecStart=/usr/bin/myapp\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "systemd-root-execution"),
            "non-root user should not be flagged"
        );
    }

    #[test]
    fn test_missing_hardening_all() {
        let content =
            "[Unit]\nDescription=My Service\n\n[Service]\nUser=myapp\nExecStart=/usr/bin/myapp\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        let hardening: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "systemd-missing-hardening")
            .collect();
        assert!(!hardening.is_empty(), "should detect missing hardening");
        assert!(hardening[0].message.contains("ProtectSystem"));
        assert!(hardening[0].message.contains("ProtectHome"));
        assert!(hardening[0].message.contains("NoNewPrivileges"));
        assert!(hardening[0].message.contains("PrivateTmp"));
    }

    #[test]
    fn test_full_hardening_ok() {
        let content = "[Unit]\nDescription=My Service\n\n[Service]\nUser=myapp\nExecStart=/usr/bin/myapp\nProtectSystem=strict\nProtectHome=yes\nNoNewPrivileges=yes\nPrivateTmp=yes\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "systemd-missing-hardening"),
            "full hardening should not be flagged"
        );
    }

    #[test]
    fn test_partial_hardening() {
        let content = "[Unit]\nDescription=My Service\n\n[Service]\nUser=myapp\nExecStart=/usr/bin/myapp\nProtectSystem=strict\nNoNewPrivileges=yes\n";
        let mut findings = Vec::new();
        analyze("myapp.service", content, &mut findings);
        let hardening: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "systemd-missing-hardening")
            .collect();
        assert!(!hardening.is_empty(), "should detect partial hardening");
        assert!(hardening[0].message.contains("ProtectHome"));
        assert!(hardening[0].message.contains("PrivateTmp"));
        assert!(!hardening[0].message.contains("ProtectSystem"));
        assert!(!hardening[0].message.contains("NoNewPrivileges"));
    }

    #[test]
    fn test_no_service_section() {
        let content = "[Unit]\nDescription=My Timer\n\n[Timer]\nOnCalendar=daily\n";
        let mut findings = Vec::new();
        analyze("mytimer.service", content, &mut findings);
        assert!(
            findings.is_empty(),
            "no [Service] section should produce no findings"
        );
    }

    #[test]
    fn test_parse_ini() {
        let content =
            "[Unit]\nDescription=Test\n\n[Service]\n# Comment\nUser=myapp\nExecStart=/bin/app\n";
        let directives = parse_ini(content);
        assert_eq!(directives.len(), 3);
        assert_eq!(directives[0].0, "Description");
        assert_eq!(directives[1].0, "User");
        assert_eq!(directives[1].1, "myapp");
        assert_eq!(directives[2].0, "ExecStart");
    }

    #[test]
    fn test_parse_ini_semicolon_comments() {
        let content = "; This is a comment\n[Service]\nExecStart=/bin/app\n";
        let directives = parse_ini(content);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].0, "ExecStart");
    }

    #[test]
    fn test_parse_ini_empty_value() {
        let content = "[Service]\nEnvironment=\n";
        let directives = parse_ini(content);
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].1, "");
    }
}
