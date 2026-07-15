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
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("anthropic_api_key"), "stdout: {}", stdout);
    assert!(
        !stdout.contains(key),
        "raw key leaked into default JSON output"
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["coverage"]["objects_scanned"], 1);
    assert!(report["coverage"]["bytes_scanned"].as_u64().unwrap() > 0);
    assert_eq!(report["coverage"]["objects_skipped"], 0);
    assert_eq!(report["coverage"]["source_errors"], serde_json::json!([]));
    assert_eq!(report["coverage"]["truncated"], false);
    assert_eq!(report["coverage"]["partial"], false);
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
    assert!(stdout.contains("\"objects_scanned\": 1"));
    assert!(stdout.contains("\"partial\": false"));
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
    assert_eq!(output.status.code(), Some(2));
    assert!(
        stdout.contains(key),
        "expected raw key in unredacted output"
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("unsafe JSON report");
    assert_eq!(report["unsafe_output"], true);
    assert!(
        report["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("live secrets"))
    );
}

#[test]
fn unredacted_human_output_includes_raw_key_and_warning() {
    let dir = tempfile::tempdir().unwrap();
    let key = "sk-ant-api03-JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ-deadbeef";
    std::fs::write(dir.path().join(".env"), format!("KEY={key}")).unwrap();

    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--unredacted")
        .output()
        .expect("run binary");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout.starts_with("!! UNREDACTED OUTPUT"));
    assert!(stdout.contains(key));
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
    assert_eq!(
        v["runs"][0]["tool"]["driver"]["name"],
        "clavenar-shadow-scanner"
    );
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
fn sarif_and_unredacted_are_mutually_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--sarif")
        .arg("--unredacted")
        .output()
        .expect("run binary");
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--unredacted") && stderr.contains("--sarif"));
}

#[test]
fn remote_sources_reject_unredacted_before_access() {
    for args in [
        ["github", "example", "--unredacted"].as_slice(),
        ["slack", "--unredacted"].as_slice(),
    ] {
        let output = Command::new(cargo_bin())
            .args(args)
            .env_remove("GITHUB_TOKEN")
            .env_remove("SLACK_BOT_TOKEN")
            .output()
            .expect("run binary");
        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("restricted to local scans"),
            "unexpected stderr: {stderr}"
        );
    }
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
    assert!(
        stdout.contains("\"total_findings\": 0"),
        "stdout: {}",
        stdout
    );
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn secrets_mode_adds_gitignored_credential_files() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    std::fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
    let key = "sk-ant-api03-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE-eZbYcXdW";
    std::fs::write(dir.path().join(".env"), format!("KEY={key}\n")).unwrap();

    let standard = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--json")
        .output()
        .expect("run standard scan");
    assert_eq!(standard.status.code(), Some(0));
    let standard_json: serde_json::Value = serde_json::from_slice(&standard.stdout).unwrap();
    assert_eq!(standard_json["total_findings"], 0);

    let secrets = Command::new(cargo_bin())
        .arg("local")
        .arg(dir.path())
        .arg("--secrets-mode")
        .arg("--json")
        .output()
        .expect("run secrets scan");
    assert_eq!(secrets.status.code(), Some(2));
    let secrets_json: serde_json::Value = serde_json::from_slice(&secrets.stdout).unwrap();
    assert!(secrets_json["total_findings"].as_u64().unwrap() > 0);
    assert!(
        secrets_json["coverage"]["objects_scanned"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(!String::from_utf8_lossy(&secrets.stdout).contains(key));
}
