//! CLI end-to-end smoke test: drop a planted secret in a tempdir, run
//! the binary against it, and assert the JSON report contains the
//! expected finding (redacted by default).

use std::process::Command;

fn cargo_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_<name> is set by cargo for any [[bin]] target during
    // `cargo test`. This is the canonical way to invoke the bin under
    // test without hardcoding a target/ path.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_clavenar-shadow-scanner"))
}

#[test]
fn local_scan_emits_redacted_json_with_planted_anthropic_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
    std::fs::write(
        dir.path().join("config.env"),
        format!("ANTHROPIC_API_KEY={}\n", key),
    )
    .unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run binary");

    // Binary exits 2 when high/critical findings are present; 0 only on
    // clean scans.
    assert_eq!(output.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("anthropic_api_key"), "stdout: {}", stdout);
    assert!(!stdout.contains(key), "raw key leaked into default JSON output");
}

#[test]
fn local_scan_clean_dir_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), "# nothing to see here\n").unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run binary");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"total_findings\": 0"));
}

#[test]
fn unredacted_flag_includes_raw_key() {
    let dir = tempfile::tempdir().unwrap();
    let key = "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-deadbeef";
    std::fs::write(dir.path().join(".env"), format!("KEY={}", key)).unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--json")
        .arg("--unredacted")
        .output()
        .expect("run binary");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(key), "expected raw key in unredacted output");
}

#[test]
fn sarif_flag_emits_v2_1_0_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let key = "sk-ant-api03-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC-deadbeef";
    std::fs::write(dir.path().join(".env"), format!("KEY={}", key)).unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--sarif")
        .output()
        .expect("run binary");
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "clavenar-shadow-scanner");
    assert!(!stdout.contains(key), "raw key leaked into SARIF output");
}

#[test]
fn sarif_and_json_are_mutually_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("README.md"), "# clean\n").unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--sarif")
        .arg("--json")
        .output()
        .expect("run binary");
    // clap exits 2 on argument-parse errors.
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--json") || stderr.contains("--sarif"),
        "expected clap conflict error, got: {}",
        stderr
    );
}

#[test]
fn severity_min_filters_below_threshold() {
    // Plant a Stripe TEST key (severity Low). Default scan would surface
    // it; --severity-min=high should drop it.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("test_setup.py"),
        "STRIPE_KEY = 'sk_test_AAAAAAAAAAAAAAAAAAAAAAAA'\n",
    )
    .unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--json")
        .arg("--severity-min")
        .arg("high")
        .output()
        .expect("run binary");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("\"total_findings\": 0"), "stdout: {}", stdout);
    assert_eq!(output.status.code(), Some(0));
}
