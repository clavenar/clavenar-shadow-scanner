//! SARIF v2.1.0 formatter
//! (<https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>).
//!
//! SARIF is the schema GitHub Advanced Security, Sonatype, Snyk, and
//! most modern code-review tools consume — emitting it lets findings
//! flow into existing security pipelines without a converter.
//!
//! Always redacted: SARIF artefacts routinely end up as PR annotations
//! and CI logs, so we never teach this path to leak.

use super::{Aggregate, Report};
use crate::detector::Severity;
use std::io::Write;

pub(super) fn write(report: &Report, mut w: impl Write) -> std::io::Result<()> {
    // BTreeMap keeps rule + result ordering deterministic across runs —
    // important for diffs in CI artefacts (e.g. PR comparison runs).
    let mut rules_by_detector: std::collections::BTreeMap<&str, &Aggregate> =
        std::collections::BTreeMap::new();
    for agg in &report.aggregates {
        // First-seen wins — and since aggregates are pre-sorted by
        // (severity, detector, fingerprint), the first one for a given
        // detector is the highest-severity instance, which is what we
        // want for the rule's defaultConfiguration.level.
        rules_by_detector.entry(&agg.detector).or_insert(agg);
    }
    let rules: Vec<serde_json::Value> = rules_by_detector
        .values()
        .map(|agg| {
            serde_json::json!({
                "id": agg.detector,
                "name": agg.detector,
                "shortDescription": { "text": format!("{} credential detected", agg.detector) },
                "defaultConfiguration": { "level": severity_to_sarif_level(agg.severity) },
            })
        })
        .collect();

    // One SARIF result per (aggregate, location). We don't collapse same-
    // fingerprint hits into one result with N locations because GitHub
    // Code Scanning expects one annotation per file:line; result.locations
    // is for related call-sites of the SAME finding, not "this same
    // secret in a different file."
    let mut results: Vec<serde_json::Value> = Vec::new();
    for agg in &report.aggregates {
        for loc in &agg.locations {
            let mut region = serde_json::json!({ "startLine": loc.line });
            // Context is pre-redacted in `Finding`'s build_context (see
            // detector.rs), so it's always safe to embed verbatim.
            if let Some(ctx) = &loc.context {
                region["snippet"] = serde_json::json!({ "text": ctx });
            }
            results.push(serde_json::json!({
                "ruleId": agg.detector,
                "level": severity_to_sarif_level(agg.severity),
                "message": {
                    "text": format!(
                        "{} credential detected (redacted: {}).",
                        agg.detector, agg.redacted
                    ),
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": loc.location },
                        "region": region,
                    }
                }],
                // Stable per-secret dedupe key — re-runs auto-resolve a
                // finding once the secret is removed.
                "fingerprints": {
                    "warden/v1": agg.fingerprint,
                },
            }));
        }
    }

    let doc = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "warden-shadow-scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/vanteguardlabs/warden-shadow-scanner",
                    "rules": rules,
                }
            },
            // Properties bag — non-standard but commonly used to carry
            // tool-specific metadata. SARIF parsers ignore unknown keys.
            "properties": {
                "source": report.source,
                "scanned_at": report.scanned_at.to_rfc3339(),
                "total_findings": report.total_findings,
            },
            "results": results,
        }],
    });
    let s = serde_json::to_string_pretty(&doc).expect("SARIF document always serializes");
    writeln!(w, "{}", s)
}

/// Map our internal severity onto SARIF's three-level system.
/// GitHub Code Scanning renders `error` red, `warning` yellow, `note`
/// blue. Critical/High both map to `error` because both are immediately
/// actionable; Medium is a warning, Low a note.
fn severity_to_sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Finding, Severity};

    fn finding(detector: &str, sev: Severity, raw: &str, loc: &str, line: u32) -> Finding {
        Finding {
            detector: detector.into(),
            severity: sev,
            location: loc.into(),
            line,
            raw_match: raw.into(),
            context: None,
        }
    }

    #[test]
    fn sarif_output_has_v2_1_0_envelope() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = Report::from_findings(
            "test",
            vec![finding("anthropic_api_key", Severity::Critical, key, "a/.env", 7)],
            false,
        );
        let mut buf = Vec::new();
        r.write_sarif(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert!(
            v["$schema"].as_str().unwrap().contains("sarif-2.1.0"),
            "schema URL must point at v2.1.0"
        );
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "warden-shadow-scanner");
    }

    #[test]
    fn sarif_output_never_includes_raw_secret() {
        // Even when the report was built with `unredacted=true`,
        // write_sarif must redact — SARIF artefacts end up in CI logs.
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = Report::from_findings(
            "test",
            vec![finding("anthropic_api_key", Severity::Critical, key, "a/.env", 7)],
            true,
        );
        let mut buf = Vec::new();
        r.write_sarif(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains(key), "raw secret leaked into SARIF output");
    }

    #[test]
    fn sarif_severity_maps_to_three_level_system() {
        assert_eq!(severity_to_sarif_level(Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(Severity::High), "error");
        assert_eq!(severity_to_sarif_level(Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(Severity::Low), "note");
    }

    #[test]
    fn sarif_results_carry_fingerprint_and_location() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = Report::from_findings(
            "test",
            vec![
                finding("anthropic_api_key", Severity::Critical, key, "a/.env", 7),
                finding("anthropic_api_key", Severity::Critical, key, "b/.env", 12),
            ],
            false,
        );
        let mut buf = Vec::new();
        r.write_sarif(&mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&buf).unwrap()).unwrap();
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        let lines: Vec<u64> = results
            .iter()
            .map(|r| r["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64().unwrap())
            .collect();
        assert!(lines.contains(&7) && lines.contains(&12));
        let fp1 = results[0]["fingerprints"]["warden/v1"].as_str().unwrap();
        let fp2 = results[1]["fingerprints"]["warden/v1"].as_str().unwrap();
        assert_eq!(fp1, fp2);
        assert_eq!(results[0]["ruleId"], "anthropic_api_key");
    }

    #[test]
    fn sarif_rules_dedupe_per_detector() {
        let r = Report::from_findings(
            "test",
            vec![
                finding("anthropic", Severity::Critical, "sk-ant-api03-AAA", "a", 1),
                finding("anthropic", Severity::Critical, "sk-ant-api03-BBB", "b", 1),
                finding("github_pat", Severity::Critical, "ghp_AAA", "c", 1),
            ],
            false,
        );
        let mut buf = Vec::new();
        r.write_sarif(&mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&buf).unwrap()).unwrap();
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&"anthropic") && ids.contains(&"github_pat"));
    }

    #[test]
    fn sarif_empty_report_still_valid() {
        let r = Report::from_findings("test", vec![], false);
        let mut buf = Vec::new();
        r.write_sarif(&mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(std::str::from_utf8(&buf).unwrap()).unwrap();
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 0);
    }
}
