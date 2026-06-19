use std::process::Command;

fn fixture_path(name: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let p = std::path::Path::new(manifest)
        .join("../../tests/fixtures/go")
        .join(name);
    p.canonicalize().unwrap_or(p).to_string_lossy().to_string()
}

fn chaffra_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_chaffra"))
}

#[test]
fn binary_health() {
    let out = chaffra_cmd()
        .args(["health", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_dead_code() {
    let out = chaffra_cmd()
        .args(["dead-code", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_security() {
    let out = chaffra_cmd()
        .args(["security", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_audit() {
    let out = chaffra_cmd()
        .args(["audit", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_hotspot() {
    let out = chaffra_cmd()
        .args(["hotspot", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_ai_quality() {
    let out = chaffra_cmd()
        .args(["ai-quality", &fixture_path("ai-quality")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_llm_defense() {
    let out = chaffra_cmd()
        .args(["llm-defense", &fixture_path("llm-defense")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_cicd_security() {
    let out = chaffra_cmd()
        .args(["cicd-security", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_dupes() {
    let out = chaffra_cmd()
        .args(["dupes", &fixture_path("duplicates")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_boundaries() {
    let out = chaffra_cmd()
        .args(["boundaries", &fixture_path("arch")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_fix_dry_run() {
    let out = chaffra_cmd()
        .args(["fix", &fixture_path("simple"), "--dry-run"])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_impact() {
    let out = chaffra_cmd()
        .args(["impact", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_modules() {
    let out = chaffra_cmd().arg("modules").output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_explain() {
    let out = chaffra_cmd()
        .args(["explain", "dead-code:unused-function"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_health_format_json() {
    let out = chaffra_cmd()
        .args(["health", &fixture_path("simple")])
        .args(["--format", "json"])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains('{'), "expected JSON output");
}

#[test]
fn binary_health_telemetry_on() {
    let out = chaffra_cmd()
        .args(["health", &fixture_path("simple")])
        .arg("--telemetry")
        .arg("on")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn binary_telemetry_status() {
    let out = chaffra_cmd()
        .args(["telemetry", "status"])
        .arg("--telemetry")
        .arg("off")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
