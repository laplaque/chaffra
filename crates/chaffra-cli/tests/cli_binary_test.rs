//! Binary integration tests — run the `chaffra` CLI against fixture directories
//! to cover `main()` command dispatch and telemetry audience forwarding.

use std::path::Path;
use std::process::Command;

fn chaffra_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_chaffra"))
}

fn fixture_path(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .to_string_lossy()
        .to_string()
}

#[test]
fn test_cli_health() {
    let output = chaffra_bin()
        .args(["health", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra health");
    assert!(
        output.status.success(),
        "health failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Health") || stdout.contains("Score") || stdout.contains("Grade"),
        "expected health output, got: {stdout}"
    );
}

#[test]
fn test_cli_dead_code() {
    let output = chaffra_bin()
        .args(["dead-code", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra dead-code");
    assert!(
        output.status.success(),
        "dead-code failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_security() {
    let output = chaffra_bin()
        .args(["security", &fixture_path("security")])
        .output()
        .expect("failed to run chaffra security");
    assert!(
        output.status.success(),
        "security failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_audit() {
    let output = chaffra_bin()
        .args(["audit", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra audit");
    assert!(
        output.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_hotspot() {
    let output = chaffra_bin()
        .args(["hotspot", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra hotspot");
    assert!(
        output.status.success(),
        "hotspot failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_ai_quality() {
    let output = chaffra_bin()
        .args(["ai-quality", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra ai-quality");
    assert!(
        output.status.success(),
        "ai-quality failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_llm_defense() {
    let output = chaffra_bin()
        .args(["llm-defense", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra llm-defense");
    assert!(
        output.status.success(),
        "llm-defense failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_cicd_security() {
    let output = chaffra_bin()
        .args(["cicd-security", &fixture_path("cicd")])
        .output()
        .expect("failed to run chaffra cicd-security");
    assert!(
        output.status.success(),
        "cicd-security failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_dupes() {
    let output = chaffra_bin()
        .args(["dupes", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra dupes");
    assert!(
        output.status.success(),
        "dupes failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_boundaries() {
    let output = chaffra_bin()
        .args(["boundaries", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra boundaries");
    assert!(
        output.status.success(),
        "boundaries failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_health_with_telemetry_off() {
    let output = chaffra_bin()
        .args(["health", &fixture_path("go/simple"), "--telemetry", "off"])
        .output()
        .expect("failed to run chaffra health --telemetry off");
    assert!(
        output.status.success(),
        "health --telemetry off failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_health_with_telemetry_on() {
    let output = chaffra_bin()
        .args(["health", &fixture_path("go/simple"), "--telemetry", "on"])
        .output()
        .expect("failed to run chaffra health --telemetry on");
    assert!(
        output.status.success(),
        "health --telemetry on failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_fix_dry_run() {
    let output = chaffra_bin()
        .args(["fix", &fixture_path("go/simple"), "--dry-run"])
        .output()
        .expect("failed to run chaffra fix --dry-run");
    assert!(
        output.status.success(),
        "fix --dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_impact() {
    let output = chaffra_bin()
        .args(["impact", &fixture_path("go/simple")])
        .output()
        .expect("failed to run chaffra impact");
    assert!(
        output.status.success(),
        "impact failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_modules() {
    let output = chaffra_bin()
        .args(["modules"])
        .output()
        .expect("failed to run chaffra modules");
    assert!(
        output.status.success(),
        "modules failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("dead-code"), "should list dead-code module");
    assert!(
        stdout.contains("complexity"),
        "should list complexity module"
    );
}

#[test]
fn test_cli_explain() {
    let output = chaffra_bin()
        .args(["explain", "unused-function"])
        .output()
        .expect("failed to run chaffra explain");
    assert!(
        output.status.success(),
        "explain failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_cli_health_json_output() {
    let output = chaffra_bin()
        .args(["health", &fixture_path("go/simple"), "--format", "json"])
        .output()
        .expect("failed to run chaffra health --format json");
    assert!(
        output.status.success(),
        "health --format json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_ok(),
        "output should be valid JSON: {stdout}"
    );
}
