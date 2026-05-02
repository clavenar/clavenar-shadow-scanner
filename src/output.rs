//! Output formatters and finding aggregation.
//!
//! [`Report`] groups raw [`Finding`]s by the SHA-256 fingerprint of the
//! secret so a key leaked in 12 files becomes one entry with 12
//! locations. The [`Report::write_human`] / [`Report::write_json`] pair
//! covers the two output modes the CLI exposes.
//!
//! Redaction is on by default. The `unredacted` flag flips secrets back
//! to plaintext at the user's explicit request — the human formatter
//! prints a banner reminding them they're producing a secrets file.

use crate::detector::{redact, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;

/// One grouped finding entry — same secret, possibly many locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregate {
    pub fingerprint: String,
    pub detector: String,
    pub severity: Severity,
    pub redacted: String,
    /// Present only when `unredacted=true` was passed to `from_findings`.
    /// Skipped from JSON when None so default output never serializes
    /// the secret.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    pub locations: Vec<Location>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub location: String,
    pub line: u32,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub source: String,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    pub aggregates: Vec<Aggregate>,
    pub total_findings: usize,
}

impl Report {
    /// Group `findings` by fingerprint and produce a `Report`.
    /// `unredacted` includes the raw secret in each aggregate when true.
    pub fn from_findings(
        source: impl Into<String>,
        findings: Vec<Finding>,
        unredacted: bool,
    ) -> Self {
        let total_findings = findings.len();
        // BTreeMap so output ordering is stable across runs (helpful for
        // diffs in CI).
        let mut buckets: BTreeMap<String, Aggregate> = BTreeMap::new();
        for f in findings {
            let fp = f.fingerprint();
            let entry = buckets.entry(fp.clone()).or_insert_with(|| Aggregate {
                fingerprint: fp.clone(),
                detector: f.detector.clone(),
                severity: f.severity,
                redacted: redact(&f.raw_match),
                raw: if unredacted { Some(f.raw_match.clone()) } else { None },
                locations: Vec::new(),
            });
            // If multiple detectors fire on the same secret, prefer the
            // higher-severity name so the report leads with the worst case.
            if f.severity < entry.severity {
                entry.severity = f.severity;
                entry.detector = f.detector.clone();
            }
            entry.locations.push(Location {
                location: f.location.clone(),
                line: f.line,
                context: f.context.clone(),
            });
        }
        // Sort aggregates by severity then detector name for stable output.
        let mut aggregates: Vec<Aggregate> = buckets.into_values().collect();
        aggregates.sort_by(|a, b| {
            a.severity
                .cmp(&b.severity)
                .then_with(|| a.detector.cmp(&b.detector))
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
        });
        Self {
            source: source.into(),
            scanned_at: chrono::Utc::now(),
            aggregates,
            total_findings,
        }
    }

    pub fn write_json(&self, mut w: impl Write) -> std::io::Result<()> {
        let s = serde_json::to_string_pretty(self).expect("Report always serializes");
        writeln!(w, "{}", s)
    }

    /// Write the report as SARIF v2.1.0 JSON
    /// (<https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>).
    /// SARIF is the standard schema GitHub Advanced Security, Sonatype,
    /// Snyk, and most modern code-review tools consume — emitting it
    /// lets shadow-scanner findings flow into existing security
    /// pipelines without an intermediate converter.
    ///
    /// Always redacted: the SARIF "message" never carries the raw
    /// secret, regardless of whether the report itself was built with
    /// `unredacted=true`. SARIF outputs typically end up as build
    /// artifacts (PR annotations, CI logs); we deliberately never
    /// teach this path to leak.
    pub fn write_sarif(&self, mut w: impl Write) -> std::io::Result<()> {
        // Each detector that actually fired becomes one `tool.driver.rules[]`
        // entry. SARIF allows the rules array to be a subset of the tool's
        // total rule catalogue, so we keep it tight.
        //
        // BTreeMap so the output ordering is deterministic across runs —
        // important for diffs in CI artefacts (e.g. PR comparison runs).
        let mut rules_by_detector: std::collections::BTreeMap<&str, &Aggregate> =
            std::collections::BTreeMap::new();
        for agg in &self.aggregates {
            // First-seen wins — but since aggregates are already sorted by
            // (severity, detector, fingerprint), the first one for a given
            // detector is also the highest-severity instance, which is
            // what we want for the rule's defaultConfiguration.level.
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

        // Each (aggregate, location) pair becomes one SARIF result. We
        // don't collapse aggregates back into one result per fingerprint
        // because SARIF tooling (GitHub Code Scanning especially) expects
        // one annotation per file:line, and result.locations[] is more
        // for related call-sites of the SAME finding, not "this same
        // secret in a different file."
        let mut results: Vec<serde_json::Value> = Vec::new();
        for agg in &self.aggregates {
            for loc in &agg.locations {
                let mut region = serde_json::json!({ "startLine": loc.line });
                // SARIF region.snippet.text carries the surrounding
                // context. We pre-redact this in `Finding`'s context
                // construction (see detector.rs), so it's always safe to
                // include verbatim.
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
                    // SARIF dedupe key: re-runs of this scanner against
                    // the same artefacts produce stable fingerprints, so
                    // GitHub Code Scanning can auto-resolve a finding
                    // when the secret is removed.
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
                // Properties bag — non-standard but commonly used to
                // carry tool-specific metadata. SARIF parsers ignore
                // unknown keys here.
                "properties": {
                    "source": self.source,
                    "scanned_at": self.scanned_at.to_rfc3339(),
                    "total_findings": self.total_findings,
                },
                "results": results,
            }],
        });
        let s = serde_json::to_string_pretty(&doc).expect("SARIF document always serializes");
        writeln!(w, "{}", s)
    }

    pub fn write_human(&self, mut w: impl Write, unredacted: bool) -> std::io::Result<()> {
        if unredacted {
            writeln!(
                w,
                "!! UNREDACTED OUTPUT — this report contains live secrets. Treat it as such."
            )?;
            writeln!(w)?;
        }
        writeln!(
            w,
            "warden-shadow-scanner :: source={}  scanned_at={}",
            self.source,
            self.scanned_at.to_rfc3339()
        )?;
        writeln!(
            w,
            "{} unique secret(s) across {} finding(s)",
            self.aggregates.len(),
            self.total_findings
        )?;
        writeln!(w)?;

        if self.aggregates.is_empty() {
            writeln!(w, "  no findings.")?;
            return Ok(());
        }

        for agg in &self.aggregates {
            let value = match &agg.raw {
                Some(raw) if unredacted => raw.clone(),
                _ => agg.redacted.clone(),
            };
            writeln!(
                w,
                "[{}] {}  fp={}",
                agg.severity.as_str().to_uppercase(),
                agg.detector,
                agg.fingerprint
            )?;
            writeln!(w, "  secret: {}", value)?;
            writeln!(w, "  found in {} location(s):", agg.locations.len())?;
            // Cap inline location output at 5 to keep the human report
            // readable; full locations live in the JSON.
            let cap = 5;
            for loc in agg.locations.iter().take(cap) {
                writeln!(w, "    - {}:{}", loc.location, loc.line)?;
            }
            if agg.locations.len() > cap {
                writeln!(
                    w,
                    "    … {} more (use --json for full list)",
                    agg.locations.len() - cap
                )?;
            }
            // Show context from the first hit as a teaser.
            if let Some(first) = agg.locations.first()
                && let Some(ctx) = &first.context {
                    writeln!(w, "  context (first hit):")?;
                    for ln in ctx.lines() {
                        writeln!(w, "    {}", ln)?;
                    }
                }
            writeln!(w)?;
        }
        Ok(())
    }
}

/// Filter findings by minimum severity. `Severity::Critical` is the
/// most-severe and orders smallest under our `Ord` impl, so "≥ severity"
/// means "ord <= chosen" in our enum direction.
pub fn filter_by_min_severity(findings: Vec<Finding>, min: Severity) -> Vec<Finding> {
    findings.into_iter().filter(|f| f.severity <= min).collect()
}

/// Map our internal severity onto SARIF's three-level system.
/// GitHub Code Scanning (the most common SARIF consumer) renders
/// `error` red, `warning` yellow, `note` blue. Critical/High both map
/// to `error` because both are immediately actionable; Medium is a
/// warning, Low is a note.
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
    use crate::detector::Severity;

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
    fn aggregates_dedupe_same_secret_across_locations() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let f1 = finding("anthropic_api_key", Severity::Critical, key, "a/.env", 1);
        let f2 = finding("anthropic_api_key", Severity::Critical, key, "b/.env", 7);
        let r = Report::from_findings("test", vec![f1, f2], false);
        assert_eq!(r.aggregates.len(), 1);
        assert_eq!(r.aggregates[0].locations.len(), 2);
        assert_eq!(r.total_findings, 2);
    }

    #[test]
    fn json_output_omits_raw_when_redacted() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = Report::from_findings(
            "test",
            vec![finding("anthropic_api_key", Severity::Critical, key, "a", 1)],
            false,
        );
        let mut buf = Vec::new();
        r.write_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains(key), "raw secret leaked into redacted output");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn json_output_includes_raw_when_unredacted() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = Report::from_findings(
            "test",
            vec![finding("anthropic_api_key", Severity::Critical, key, "a", 1)],
            true,
        );
        let mut buf = Vec::new();
        r.write_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains(key));
    }

    #[test]
    fn human_output_with_unredacted_includes_warning_banner() {
        let r = Report::from_findings("test", vec![], true);
        let mut buf = Vec::new();
        r.write_human(&mut buf, true).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("UNREDACTED"));
    }

    #[test]
    fn min_severity_filter_keeps_higher_only() {
        let key1 = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let key2 = "low-severity-thing";
        let inputs = vec![
            finding("anthropic_api_key", Severity::Critical, key1, "a", 1),
            finding("low_thing", Severity::Low, key2, "b", 1),
        ];
        let kept = filter_by_min_severity(inputs, Severity::High);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].detector, "anthropic_api_key");
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
            true, // unredacted
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
        // Two locations -> two SARIF results, each pinning its file:line.
        assert_eq!(results.len(), 2);
        let lines: Vec<u64> = results
            .iter()
            .map(|r| r["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64().unwrap())
            .collect();
        assert!(lines.contains(&7) && lines.contains(&12));
        // Fingerprint is the same on both (same secret).
        let fp1 = results[0]["fingerprints"]["warden/v1"].as_str().unwrap();
        let fp2 = results[1]["fingerprints"]["warden/v1"].as_str().unwrap();
        assert_eq!(fp1, fp2);
        // ruleId matches the detector.
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
        // Two unique detectors -> two rules, regardless of how many
        // findings each fired.
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

    #[test]
    fn aggregates_sort_by_severity_first() {
        let agg = Report::from_findings(
            "test",
            vec![
                finding("low_thing", Severity::Low, "low-secret-dummy", "a", 1),
                finding("anthropic", Severity::Critical, "sk-ant-api03-AAA", "b", 1),
                finding("github_pat", Severity::Critical, "ghp_AAA", "c", 1),
            ],
            false,
        );
        // Critical entries lead, low last.
        assert_eq!(agg.aggregates[0].severity, Severity::Critical);
        assert_eq!(agg.aggregates.last().unwrap().severity, Severity::Low);
    }
}
