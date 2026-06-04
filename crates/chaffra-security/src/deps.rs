//! Dependency CVE scanning -- parse manifests and check for known vulnerabilities.
//!
//! Operates in offline/mock mode: no network calls. Vulnerability patterns are
//! detected from manifest structure and known-bad version ranges.

use chaffra_core::diagnostic::{Action, FileInfo, Finding, Location, Severity};
use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

/// A known vulnerable dependency range.
#[derive(Debug, Clone)]
pub struct VulnerableRange {
    /// Package name pattern (exact or prefix match).
    pub package: &'static str,
    /// Minimum affected version (inclusive). Empty means any version.
    pub min_version: &'static str,
    /// Maximum affected version (exclusive). Empty means unbounded.
    pub max_version: &'static str,
    /// CVE or advisory identifier.
    pub advisory: &'static str,
    /// Description of the vulnerability.
    pub description: &'static str,
    /// Severity of the vulnerability.
    pub severity: Severity,
}

/// Known vulnerability database (offline, curated).
const KNOWN_VULNS: &[VulnerableRange] = &[
    // Python
    VulnerableRange {
        package: "django",
        min_version: "0",
        max_version: "3.2.25",
        advisory: "CVE-2024-27351",
        description: "Django potential ReDoS in truncatechars_html",
        severity: Severity::Warning,
    },
    VulnerableRange {
        package: "flask",
        min_version: "0",
        max_version: "2.3.2",
        advisory: "CVE-2023-30861",
        description: "Flask session cookie set on every response",
        severity: Severity::Warning,
    },
    VulnerableRange {
        package: "requests",
        min_version: "0",
        max_version: "2.31.0",
        advisory: "CVE-2023-32681",
        description: "Requests unintended leak of Proxy-Authorization header",
        severity: Severity::Warning,
    },
    VulnerableRange {
        package: "urllib3",
        min_version: "0",
        max_version: "2.0.7",
        advisory: "CVE-2023-45803",
        description: "urllib3 request body not stripped on redirect",
        severity: Severity::Warning,
    },
    VulnerableRange {
        package: "pyyaml",
        min_version: "0",
        max_version: "6.0.1",
        advisory: "CVE-2024-6156",
        description: "PyYAML arbitrary code execution via yaml.load",
        severity: Severity::Error,
    },
    VulnerableRange {
        package: "pillow",
        min_version: "0",
        max_version: "10.2.0",
        advisory: "CVE-2024-28219",
        description: "Pillow buffer overflow in image processing",
        severity: Severity::Error,
    },
    VulnerableRange {
        package: "cryptography",
        min_version: "0",
        max_version: "42.0.0",
        advisory: "CVE-2024-26130",
        description: "cryptography NULL pointer dereference in PKCS#12",
        severity: Severity::Warning,
    },
    // Go
    VulnerableRange {
        package: "golang.org/x/net",
        min_version: "0",
        max_version: "0.23.0",
        advisory: "CVE-2024-24790",
        description: "golang.org/x/net HTTP/2 rapid reset attack",
        severity: Severity::Error,
    },
    VulnerableRange {
        package: "golang.org/x/crypto",
        min_version: "0",
        max_version: "0.17.0",
        advisory: "CVE-2023-48795",
        description: "golang.org/x/crypto SSH Terrapin prefix truncation attack",
        severity: Severity::Error,
    },
    VulnerableRange {
        package: "google.golang.org/grpc",
        min_version: "0",
        max_version: "1.56.3",
        advisory: "CVE-2023-44487",
        description: "gRPC-Go rapid reset attack denial of service",
        severity: Severity::Error,
    },
    VulnerableRange {
        package: "github.com/gin-gonic/gin",
        min_version: "0",
        max_version: "1.9.1",
        advisory: "CVE-2023-29401",
        description: "Gin insufficient type validation in binding",
        severity: Severity::Warning,
    },
    // Node.js / npm
    VulnerableRange {
        package: "express",
        min_version: "0",
        max_version: "4.19.2",
        advisory: "CVE-2024-29041",
        description: "Express.js open redirect vulnerability",
        severity: Severity::Warning,
    },
    VulnerableRange {
        package: "jsonwebtoken",
        min_version: "0",
        max_version: "9.0.0",
        advisory: "CVE-2022-23529",
        description: "jsonwebtoken insecure JWT implementation",
        severity: Severity::Error,
    },
    VulnerableRange {
        package: "axios",
        min_version: "0",
        max_version: "1.6.0",
        advisory: "CVE-2023-45857",
        description: "Axios CSRF vulnerability via cross-site cookie forwarding",
        severity: Severity::Warning,
    },
    // Rust / Cargo
    VulnerableRange {
        package: "tokio",
        min_version: "0",
        max_version: "1.24.2",
        advisory: "RUSTSEC-2023-0001",
        description: "tokio unexpected panic in `ReadHalf::unsplit`",
        severity: Severity::Warning,
    },
    VulnerableRange {
        package: "hyper",
        min_version: "0",
        max_version: "0.14.27",
        advisory: "RUSTSEC-2023-0034",
        description: "hyper insufficient validation of HTTP headers",
        severity: Severity::Warning,
    },
];

/// Parsed dependency with name and version.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedDep {
    pub name: String,
    pub version: String,
    pub line: u32,
}

/// Manifest type detected.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ManifestType {
    GoMod,
    RequirementsTxt,
    CargoLock,
    PackageLockJson,
    Unknown,
}

/// Detect manifest type from file path.
pub fn detect_manifest_type(path: &str) -> ManifestType {
    let filename = path.rsplit('/').next().unwrap_or(path);
    match filename {
        "go.mod" => ManifestType::GoMod,
        "requirements.txt" => ManifestType::RequirementsTxt,
        "Cargo.lock" => ManifestType::CargoLock,
        "package-lock.json" => ManifestType::PackageLockJson,
        _ => ManifestType::Unknown,
    }
}

/// Check if a file is a dependency manifest.
pub fn is_manifest(path: &str) -> bool {
    detect_manifest_type(path) != ManifestType::Unknown
}

/// Parse dependencies from a manifest file.
pub fn parse_manifest(file: &FileInfo) -> Vec<ParsedDep> {
    let manifest_type = detect_manifest_type(&file.path);
    let source = String::from_utf8_lossy(&file.content);

    match manifest_type {
        ManifestType::GoMod => parse_go_mod(&source),
        ManifestType::RequirementsTxt => parse_requirements_txt(&source),
        ManifestType::CargoLock => parse_cargo_lock(&source),
        ManifestType::PackageLockJson => parse_package_lock_json(&source),
        ManifestType::Unknown => vec![],
    }
}

/// Parse go.mod file.
fn parse_go_mod(source: &str) -> Vec<ParsedDep> {
    static GO_MOD_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s+(\S+)\s+(v[\d.]+(?:-\S+)?)").unwrap());

    let mut deps = Vec::new();
    let mut in_require = false;

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("require (") || trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" {
            in_require = false;
            continue;
        }

        if in_require {
            if let Some(caps) = GO_MOD_RE.captures(line) {
                let name = caps.get(1).unwrap().as_str().to_owned();
                let version = caps
                    .get(2)
                    .unwrap()
                    .as_str()
                    .trim_start_matches('v')
                    .to_owned();
                deps.push(ParsedDep {
                    name,
                    version,
                    line: (line_num + 1) as u32,
                });
            }
        } else if trimmed.starts_with("require ") && !trimmed.contains('(') {
            // Single-line require: `require example.com/foo v1.2.3`
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 3 {
                deps.push(ParsedDep {
                    name: parts[1].to_owned(),
                    version: parts[2].trim_start_matches('v').to_owned(),
                    line: (line_num + 1) as u32,
                });
            }
        }
    }

    deps
}

/// Parse requirements.txt file.
fn parse_requirements_txt(source: &str) -> Vec<ParsedDep> {
    static REQ_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)==([\d.]+(?:\.\w+)?)").unwrap()
    });

    let mut deps = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }

        if let Some(caps) = REQ_RE.captures(trimmed) {
            let name = caps.get(1).unwrap().as_str().to_lowercase();
            // Strip extras like [security].
            let name = if let Some(pos) = name.find('[') {
                name[..pos].to_owned()
            } else {
                name
            };
            let version = caps.get(2).unwrap().as_str().to_owned();
            deps.push(ParsedDep {
                name,
                version,
                line: (line_num + 1) as u32,
            });
        }
    }

    deps
}

/// Parse Cargo.lock file.
fn parse_cargo_lock(source: &str) -> Vec<ParsedDep> {
    let mut deps = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_line: u32 = 0;

    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            current_name = None;
            current_line = (line_num + 1) as u32;
            continue;
        }

        if trimmed.starts_with("name = ") {
            let name = trimmed
                .trim_start_matches("name = ")
                .trim_matches('"')
                .to_owned();
            current_name = Some(name);
        }

        if trimmed.starts_with("version = ") {
            if let Some(name) = current_name.take() {
                let version = trimmed
                    .trim_start_matches("version = ")
                    .trim_matches('"')
                    .to_owned();
                deps.push(ParsedDep {
                    name,
                    version,
                    line: current_line,
                });
            }
        }
    }

    deps
}

/// Parse package-lock.json file (simplified: extract top-level dependencies).
fn parse_package_lock_json(source: &str) -> Vec<ParsedDep> {
    // Simple line-by-line approach to avoid full JSON parsing overhead.
    // Looks for patterns like: "package-name": { "version": "1.2.3" }
    static PKG_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s+"node_modules/([^"]+)":\s*\{"#).unwrap());
    static VER_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"^\s+"version":\s*"([^"]+)""#).unwrap());

    let mut deps = Vec::new();
    let mut current_pkg: Option<(String, u32)> = None;

    for (line_num, line) in source.lines().enumerate() {
        if let Some(caps) = PKG_RE.captures(line) {
            let name = caps.get(1).unwrap().as_str().to_owned();
            // Extract just the package name from nested paths.
            let name = if name.contains('/') {
                // Could be @scope/pkg or nested paths.
                let parts: Vec<&str> = name.rsplitn(2, "node_modules/").collect();
                parts[0].to_owned()
            } else {
                name
            };
            current_pkg = Some((name, (line_num + 1) as u32));
        } else if let Some(caps) = VER_RE.captures(line) {
            if let Some((name, pkg_line)) = current_pkg.take() {
                let version = caps.get(1).unwrap().as_str().to_owned();
                deps.push(ParsedDep {
                    name,
                    version,
                    line: pkg_line,
                });
            }
        }
    }

    deps
}

/// Scan a manifest file for known vulnerable dependencies.
pub fn scan_manifest(file: &FileInfo) -> Vec<Finding> {
    if !is_manifest(&file.path) {
        return vec![];
    }

    let deps = parse_manifest(file);
    let mut findings = Vec::new();

    for dep in &deps {
        for vuln in KNOWN_VULNS {
            if matches_vulnerable_dep(dep, vuln) {
                findings.push(Finding {
                    rule_id: "vulnerable-dependency".to_owned(),
                    message: format!(
                        "{} {} has known vulnerability {}: {}",
                        dep.name, dep.version, vuln.advisory, vuln.description
                    ),
                    severity: vuln.severity,
                    location: Location {
                        file: file.path.clone(),
                        start_line: dep.line,
                        end_line: dep.line,
                        start_column: 0,
                        end_column: 0,
                    },
                    confidence: 0.95,
                    actions: vec![Action {
                        description: format!(
                            "Upgrade {} to a version >= {}",
                            dep.name, vuln.max_version
                        ),
                        auto_fixable: false,
                        edits: vec![],
                    }],
                    metadata: {
                        let mut m = HashMap::new();
                        m.insert("advisory".to_owned(), vuln.advisory.to_owned());
                        m.insert("package".to_owned(), dep.name.clone());
                        m.insert("installed_version".to_owned(), dep.version.clone());
                        m.insert("fixed_version".to_owned(), vuln.max_version.to_owned());
                        m
                    },
                });
            }
        }
    }

    findings
}

/// Check if a parsed dependency matches a vulnerable range.
fn matches_vulnerable_dep(dep: &ParsedDep, vuln: &VulnerableRange) -> bool {
    // Package name match (case-insensitive, normalize hyphens/underscores).
    let dep_name = dep.name.to_lowercase().replace('_', "-");
    let vuln_name = vuln.package.to_lowercase().replace('_', "-");

    if dep_name != vuln_name {
        return false;
    }

    // Version comparison using semver-like logic.
    version_in_range(&dep.version, vuln.min_version, vuln.max_version)
}

/// Check if a version string falls within [min_version, max_version).
pub fn version_in_range(version: &str, min: &str, max: &str) -> bool {
    let ver = parse_version(version);

    if !min.is_empty() && min != "0" {
        let min_ver = parse_version(min);
        if compare_versions(&ver, &min_ver) < 0 {
            return false;
        }
    }

    if !max.is_empty() {
        let max_ver = parse_version(max);
        if compare_versions(&ver, &max_ver) >= 0 {
            return false;
        }
    }

    true
}

/// Parse a version string into a vector of numeric components.
fn parse_version(s: &str) -> Vec<u64> {
    s.split('.')
        .map(|part| {
            // Strip any pre-release suffix (e.g., "1.0.0-beta1" -> "1", "0", "0").
            let numeric = part
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>();
            numeric.parse().unwrap_or(0)
        })
        .collect()
}

/// Compare two version vectors. Returns -1, 0, or 1.
fn compare_versions(a: &[u64], b: &[u64]) -> i32 {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        if av < bv {
            return -1;
        }
        if av > bv {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file(path: &str, content: &str) -> FileInfo {
        FileInfo {
            path: path.to_owned(),
            content: content.as_bytes().to_vec(),
        }
    }

    // --- detect_manifest_type ---

    #[test]
    fn test_detect_manifest_type() {
        let cases = vec![
            ("go.mod", ManifestType::GoMod),
            ("path/to/go.mod", ManifestType::GoMod),
            ("requirements.txt", ManifestType::RequirementsTxt),
            ("Cargo.lock", ManifestType::CargoLock),
            ("package-lock.json", ManifestType::PackageLockJson),
            ("random.txt", ManifestType::Unknown),
            ("Cargo.toml", ManifestType::Unknown),
        ];
        for (path, expected) in cases {
            assert_eq!(
                detect_manifest_type(path),
                expected,
                "detect_manifest_type({path:?})"
            );
        }
    }

    // --- is_manifest ---

    #[test]
    fn test_is_manifest() {
        assert!(is_manifest("go.mod"));
        assert!(is_manifest("requirements.txt"));
        assert!(is_manifest("Cargo.lock"));
        assert!(is_manifest("package-lock.json"));
        assert!(!is_manifest("main.go"));
        assert!(!is_manifest("setup.py"));
    }

    // --- version comparison ---

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_version("0.14.27"), vec![0, 14, 27]);
        assert_eq!(parse_version("1.0.0-beta1"), vec![1, 0, 0]);
    }

    #[test]
    fn test_compare_versions() {
        let cases = vec![
            (vec![1, 2, 3], vec![1, 2, 3], 0),
            (vec![1, 2, 3], vec![1, 2, 4], -1),
            (vec![1, 3, 0], vec![1, 2, 4], 1),
            (vec![2, 0, 0], vec![1, 99, 99], 1),
            (vec![1, 0], vec![1, 0, 0], 0),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                compare_versions(&a, &b),
                expected,
                "compare_versions({a:?}, {b:?})"
            );
        }
    }

    #[test]
    fn test_version_in_range() {
        let cases = vec![
            // Version 1.0.0, range [0, 2.0.0) -> in range
            ("1.0.0", "0", "2.0.0", true),
            // Version 2.0.0, range [0, 2.0.0) -> NOT in range (exclusive upper)
            ("2.0.0", "0", "2.0.0", false),
            // Version 0.14.26, range [0, 0.14.27) -> in range
            ("0.14.26", "0", "0.14.27", true),
            // Version 0.14.27, range [0, 0.14.27) -> NOT in range
            ("0.14.27", "0", "0.14.27", false),
            // Version 2.30.0, range [0, 2.31.0) -> in range
            ("2.30.0", "0", "2.31.0", true),
        ];
        for (ver, min, max, expected) in cases {
            assert_eq!(
                version_in_range(ver, min, max),
                expected,
                "version_in_range({ver:?}, {min:?}, {max:?})"
            );
        }
    }

    // --- go.mod parsing ---

    #[test]
    fn test_parse_go_mod() {
        let file = make_file(
            "go.mod",
            r#"module example.com/myapp

go 1.21

require (
    golang.org/x/net v0.20.0
    golang.org/x/crypto v0.16.0
    github.com/gin-gonic/gin v1.9.0
)
"#,
        );
        let deps = parse_manifest(&file);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "golang.org/x/net");
        assert_eq!(deps[0].version, "0.20.0");
        assert_eq!(deps[1].name, "golang.org/x/crypto");
        assert_eq!(deps[1].version, "0.16.0");
        assert_eq!(deps[2].name, "github.com/gin-gonic/gin");
        assert_eq!(deps[2].version, "1.9.0");
    }

    #[test]
    fn test_parse_go_mod_single_require() {
        let file = make_file(
            "go.mod",
            "module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/net v0.10.0\n",
        );
        let deps = parse_manifest(&file);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "golang.org/x/net");
        assert_eq!(deps[0].version, "0.10.0");
    }

    // --- requirements.txt parsing ---

    #[test]
    fn test_parse_requirements_txt() {
        let file = make_file(
            "requirements.txt",
            r#"# Main dependencies
django==3.2.20
flask==2.3.0
requests==2.28.0
# Dev deps
pyyaml==5.4.1
"#,
        );
        let deps = parse_manifest(&file);
        assert_eq!(deps.len(), 4);
        assert_eq!(deps[0].name, "django");
        assert_eq!(deps[0].version, "3.2.20");
        assert_eq!(deps[1].name, "flask");
        assert_eq!(deps[1].version, "2.3.0");
        assert_eq!(deps[2].name, "requests");
        assert_eq!(deps[2].version, "2.28.0");
        assert_eq!(deps[3].name, "pyyaml");
        assert_eq!(deps[3].version, "5.4.1");
    }

    #[test]
    fn test_parse_requirements_txt_with_extras() {
        let file = make_file(
            "requirements.txt",
            "requests[security]==2.28.0\ncryptography==41.0.0\n",
        );
        let deps = parse_manifest(&file);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].name, "requests");
        assert_eq!(deps[0].version, "2.28.0");
    }

    // --- Cargo.lock parsing ---

    #[test]
    fn test_parse_cargo_lock() {
        let file = make_file(
            "Cargo.lock",
            r#"[[package]]
name = "tokio"
version = "1.24.0"

[[package]]
name = "hyper"
version = "0.14.20"

[[package]]
name = "serde"
version = "1.0.200"
"#,
        );
        let deps = parse_manifest(&file);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "tokio");
        assert_eq!(deps[0].version, "1.24.0");
        assert_eq!(deps[1].name, "hyper");
        assert_eq!(deps[1].version, "0.14.20");
    }

    // --- package-lock.json parsing ---

    #[test]
    fn test_parse_package_lock_json() {
        let file = make_file(
            "package-lock.json",
            r#"{
  "name": "myapp",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/express": {
      "version": "4.18.0"
    },
    "node_modules/jsonwebtoken": {
      "version": "8.5.1"
    },
    "node_modules/axios": {
      "version": "1.5.0"
    }
  }
}
"#,
        );
        let deps = parse_manifest(&file);
        assert_eq!(deps.len(), 3);
        assert_eq!(deps[0].name, "express");
        assert_eq!(deps[0].version, "4.18.0");
        assert_eq!(deps[1].name, "jsonwebtoken");
        assert_eq!(deps[1].version, "8.5.1");
    }

    // --- Vulnerability matching ---

    #[test]
    fn test_matches_vulnerable_dep_go() {
        let dep = ParsedDep {
            name: "golang.org/x/net".to_owned(),
            version: "0.20.0".to_owned(),
            line: 5,
        };
        let vuln = &KNOWN_VULNS
            .iter()
            .find(|v| v.package == "golang.org/x/net")
            .unwrap();
        assert!(
            matches_vulnerable_dep(&dep, vuln),
            "golang.org/x/net 0.20.0 should match CVE range"
        );
    }

    #[test]
    fn test_matches_vulnerable_dep_fixed() {
        let dep = ParsedDep {
            name: "golang.org/x/net".to_owned(),
            version: "0.23.0".to_owned(),
            line: 5,
        };
        let vuln = &KNOWN_VULNS
            .iter()
            .find(|v| v.package == "golang.org/x/net")
            .unwrap();
        assert!(
            !matches_vulnerable_dep(&dep, vuln),
            "golang.org/x/net 0.23.0 should NOT match (fixed version)"
        );
    }

    #[test]
    fn test_matches_vulnerable_dep_python() {
        let dep = ParsedDep {
            name: "django".to_owned(),
            version: "3.2.20".to_owned(),
            line: 1,
        };
        let vuln = &KNOWN_VULNS.iter().find(|v| v.package == "django").unwrap();
        assert!(
            matches_vulnerable_dep(&dep, vuln),
            "django 3.2.20 should match CVE range"
        );
    }

    #[test]
    fn test_no_match_different_package() {
        let dep = ParsedDep {
            name: "some-other-package".to_owned(),
            version: "1.0.0".to_owned(),
            line: 1,
        };
        for vuln in KNOWN_VULNS {
            assert!(
                !matches_vulnerable_dep(&dep, vuln),
                "random package should not match any vulnerability"
            );
        }
    }

    // --- Full manifest scan ---

    #[test]
    fn test_scan_go_mod_finds_vulns() {
        let file = make_file(
            "go.mod",
            r#"module example.com/myapp

go 1.21

require (
    golang.org/x/net v0.20.0
    golang.org/x/crypto v0.16.0
)
"#,
        );
        let findings = scan_manifest(&file);
        assert!(
            !findings.is_empty(),
            "should find vulnerabilities in go.mod"
        );
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id == "vulnerable-dependency")
        );
        // Both packages should be flagged.
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("golang.org/x/net"))
        );
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("golang.org/x/crypto"))
        );
    }

    #[test]
    fn test_scan_requirements_finds_vulns() {
        let file = make_file(
            "requirements.txt",
            "flask==2.3.0\nrequests==2.28.0\npyyaml==5.4.1\n",
        );
        let findings = scan_manifest(&file);
        assert!(
            !findings.is_empty(),
            "should find vulnerabilities in requirements.txt"
        );
        assert!(findings.iter().any(|f| f.message.contains("flask")));
        assert!(findings.iter().any(|f| f.message.contains("requests")));
        assert!(findings.iter().any(|f| f.message.contains("pyyaml")));
    }

    #[test]
    fn test_scan_cargo_lock_finds_vulns() {
        let file = make_file(
            "Cargo.lock",
            "[[package]]\nname = \"tokio\"\nversion = \"1.24.0\"\n\n[[package]]\nname = \"hyper\"\nversion = \"0.14.20\"\n",
        );
        let findings = scan_manifest(&file);
        assert!(
            !findings.is_empty(),
            "should find vulnerabilities in Cargo.lock"
        );
        assert!(findings.iter().any(|f| f.message.contains("tokio")));
        assert!(findings.iter().any(|f| f.message.contains("hyper")));
    }

    #[test]
    fn test_scan_package_lock_finds_vulns() {
        let file = make_file(
            "package-lock.json",
            r#"{
  "packages": {
    "node_modules/express": {
      "version": "4.18.0"
    },
    "node_modules/jsonwebtoken": {
      "version": "8.5.1"
    }
  }
}
"#,
        );
        let findings = scan_manifest(&file);
        assert!(
            !findings.is_empty(),
            "should find vulnerabilities in package-lock.json"
        );
    }

    #[test]
    fn test_scan_non_manifest_returns_empty() {
        let file = make_file("main.go", "package main\n");
        let findings = scan_manifest(&file);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_clean_manifest() {
        // All versions are above known vulnerability ranges.
        let file = make_file(
            "requirements.txt",
            "django==4.2.0\nflask==3.0.0\nrequests==2.31.0\n",
        );
        let findings = scan_manifest(&file);
        assert!(
            findings.is_empty(),
            "clean manifest should have no findings: {findings:?}"
        );
    }
}
