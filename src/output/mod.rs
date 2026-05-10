//! Output formatters and finding aggregation.
//!
//! [`Report`] groups raw [`Finding`]s by the SHA-256 fingerprint of the
//! secret so a key leaked in 12 files becomes one entry with 12
//! locations. The CLI exposes three modes: human, JSON, and SARIF (the
//! last lives in the [`sarif`] submodule).
//!
//! Redaction is on by default. The `unredacted` flag flips secrets back
//! to plaintext at the user's explicit request — the human formatter
//! prints a banner reminding them they're producing a secrets file.
//! SARIF ignores `unredacted` entirely; see [`sarif`].

mod sarif;

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

    /// Write the report as SARIF v2.1.0. Always redacted regardless of
    /// the `unredacted` flag the report was built with — see [`sarif`].
    pub fn write_sarif(&self, w: impl Write) -> std::io::Result<()> {
        sarif::write(self, w)
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
