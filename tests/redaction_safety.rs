//! Default-serializer non-disclosure corpus for multi-secret context.

use clavenar_shadow_scanner::{output::Report, scan_text};

#[test]
fn every_default_serializer_redacts_the_complete_multi_secret_corpus() {
    let anthropic = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
    let github = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let openai = "sk-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234";
    let pem_body_one = "MIIEpAIBAAKCAQEA7SyntheticPrivateKeyBodyLineOne";
    let pem_body_two = "SyntheticPrivateKeyBodyLineTwo9xYz";
    let pem = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{pem_body_one}\n{pem_body_two}\n-----END RSA PRIVATE KEY-----"
    );
    let input = format!("same_line={anthropic} {github}\napi_key=\"{openai}\"\n{pem}\n");
    let findings = scan_text(&input, "synthetic-corpus");
    assert!(findings.len() >= 4, "expected the complete detector corpus");

    for finding in &findings {
        let serialized = serde_json::to_string(finding).unwrap();
        let debug = format!("{finding:?}");
        for secret in [anthropic, github, openai, pem_body_one, pem_body_two] {
            assert!(!serialized.contains(secret));
            assert!(!debug.contains(secret));
            if let Some(context) = &finding.context {
                assert!(
                    !context.contains(secret),
                    "complete credential appeared in finding context"
                );
            }
        }
    }

    let report = Report::from_findings("synthetic-corpus", findings);
    let mut human = Vec::new();
    report.write_human(&mut human).unwrap();
    let mut json = Vec::new();
    report.write_json(&mut json).unwrap();
    let mut sarif = Vec::new();
    report.write_sarif(&mut sarif).unwrap();

    for output in [human, json, sarif] {
        let output = String::from_utf8(output).unwrap();
        for secret in [
            anthropic,
            github,
            openai,
            pem.as_str(),
            pem_body_one,
            pem_body_two,
        ] {
            assert!(
                !output.contains(secret),
                "complete credential appeared in a default serializer"
            );
        }
    }
}
