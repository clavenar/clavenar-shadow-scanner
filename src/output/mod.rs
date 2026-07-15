//! Output formatters and finding aggregation.
//!
//! [`Report`] groups safe [`Finding`]s by fingerprint so a key leaked in
//! 12 files becomes one entry with 12 locations. Its data model contains no
//! recoverable raw value. Explicit local unsafe output uses the separate
//! [`UnsafeReport`] type.
//!
//! SARIF accepts only [`Report`]; see [`sarif`].

mod sarif;

use crate::detector::{Finding, Severity, UnsafeFinding};
use crate::sources::{CoverageEvaluation, DEFAULT_MAX_PARTIAL_PERCENT, ScanCoverage, ScanOutcome};
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
    #[serde(default)]
    pub coverage: ScanCoverage,
    #[serde(default)]
    pub coverage_evaluation: CoverageEvaluation,
    pub aggregates: Vec<Aggregate>,
    pub total_findings: usize,
}

impl Report {
    /// Group `findings` by fingerprint and produce a `Report`.
    pub fn from_findings(source: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self::from_outcome(source, ScanOutcome::from_findings(findings))
    }

    /// Group a typed scan outcome while preserving its source coverage.
    pub fn from_outcome(source: impl Into<String>, outcome: ScanOutcome<Finding>) -> Self {
        Self::from_outcome_with_threshold(source, outcome, DEFAULT_MAX_PARTIAL_PERCENT)
    }

    pub fn from_outcome_with_threshold(
        source: impl Into<String>,
        outcome: ScanOutcome<Finding>,
        max_partial_percent: f64,
    ) -> Self {
        let (findings, coverage) = outcome.into_parts();
        Self::build(source, findings, coverage, max_partial_percent)
    }

    fn build(
        source: impl Into<String>,
        findings: Vec<Finding>,
        coverage: ScanCoverage,
        max_partial_percent: f64,
    ) -> Self {
        let total_findings = findings.len();
        let coverage_evaluation = CoverageEvaluation::evaluate(&coverage, max_partial_percent);
        // BTreeMap so output ordering is stable across runs (helpful for
        // diffs in CI).
        let mut buckets: BTreeMap<String, Aggregate> = BTreeMap::new();
        for f in findings {
            let fp = f.fingerprint.clone();
            let entry = buckets.entry(fp.clone()).or_insert_with(|| Aggregate {
                fingerprint: fp.clone(),
                detector: f.detector.clone(),
                severity: f.severity,
                redacted: f.redacted.clone(),
                locations: Vec::new(),
            });
            // If multiple detectors fire on the same secret, prefer the
            // higher-severity name so the report leads with the worst case.
            if f.severity < entry.severity {
                entry.severity = f.severity;
                entry.detector = f.detector.clone();
            }
            // Dedupe by (location, line): a vendor detector and the
            // generic backstop often fire on the same physical hit
            // (`OPENAI_API_KEY="sk-…"` matches both `openai_api_key`
            // and `generic_high_entropy_secret`). Without this guard
            // the README's "12 files → 12 locations" promise inflates
            // to 24 when two detectors agree on every line.
            let dup = entry
                .locations
                .iter()
                .any(|l| l.location == f.location && l.line == f.line);
            if !dup {
                entry.locations.push(Location {
                    location: f.location.clone(),
                    line: f.line,
                    context: f.context.clone(),
                });
            }
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
            coverage,
            coverage_evaluation,
            aggregates,
            total_findings,
        }
    }

    pub fn write_json(&self, mut w: impl Write) -> std::io::Result<()> {
        let s = serde_json::to_string_pretty(self).expect("Report always serializes");
        writeln!(w, "{}", s)
    }

    /// Write the report as SARIF v2.1.0. The accepted model has no raw value.
    pub fn write_sarif(&self, w: impl Write) -> std::io::Result<()> {
        sarif::write(self, w)
    }

    pub fn write_human(&self, mut w: impl Write) -> std::io::Result<()> {
        writeln!(
            w,
            "clavenar-shadow-scanner :: source={}  scanned_at={}",
            self.source,
            self.scanned_at.to_rfc3339()
        )?;
        writeln!(
            w,
            "{} unique secret(s) across {} finding(s)",
            self.aggregates.len(),
            self.total_findings
        )?;
        write_human_coverage(&self.coverage, &self.coverage_evaluation, &mut w)?;
        writeln!(w)?;

        if self.aggregates.is_empty() {
            writeln!(w, "  no findings.")?;
            return Ok(());
        }

        for agg in &self.aggregates {
            writeln!(
                w,
                "[{}] {}  fp={}",
                agg.severity.as_str().to_uppercase(),
                agg.detector,
                agg.fingerprint
            )?;
            writeln!(w, "  secret: {}", agg.redacted)?;
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
                && let Some(ctx) = &first.context
            {
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

pub const UNSAFE_OUTPUT_WARNING: &str =
    "UNREDACTED OUTPUT — this report contains live secrets. Treat it as such.";

/// Secret-bearing aggregate used only by explicit local unsafe output.
#[derive(Serialize)]
pub struct UnsafeAggregate {
    pub fingerprint: String,
    pub detector: String,
    pub severity: Severity,
    pub redacted: String,
    pub raw: String,
    pub locations: Vec<Location>,
}

/// Explicitly secret-bearing report. It cannot be constructed from safe
/// findings, has no SARIF writer, and every serialization carries a warning.
#[derive(Serialize)]
pub struct UnsafeReport {
    pub unsafe_output: bool,
    pub warning: &'static str,
    pub source: String,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    pub coverage: ScanCoverage,
    pub coverage_evaluation: CoverageEvaluation,
    pub aggregates: Vec<UnsafeAggregate>,
    pub total_findings: usize,
}

impl UnsafeReport {
    pub fn from_findings(source: impl Into<String>, findings: Vec<UnsafeFinding>) -> Self {
        Self::from_outcome(source, ScanOutcome::from_findings(findings))
    }

    pub fn from_outcome(source: impl Into<String>, outcome: ScanOutcome<UnsafeFinding>) -> Self {
        Self::from_outcome_with_threshold(source, outcome, DEFAULT_MAX_PARTIAL_PERCENT)
    }

    pub fn from_outcome_with_threshold(
        source: impl Into<String>,
        outcome: ScanOutcome<UnsafeFinding>,
        max_partial_percent: f64,
    ) -> Self {
        let (findings, coverage) = outcome.into_parts();
        let mut raw_by_fingerprint = BTreeMap::new();
        let safe_findings = findings
            .into_iter()
            .map(|finding| {
                let (safe, raw) = finding.into_parts();
                raw_by_fingerprint
                    .entry(safe.fingerprint.clone())
                    .or_insert(raw);
                safe
            })
            .collect();
        let report = Report::build(source, safe_findings, coverage, max_partial_percent);
        let aggregates = report
            .aggregates
            .into_iter()
            .map(|aggregate| UnsafeAggregate {
                raw: raw_by_fingerprint
                    .remove(&aggregate.fingerprint)
                    .expect("unsafe finding has matching raw value"),
                fingerprint: aggregate.fingerprint,
                detector: aggregate.detector,
                severity: aggregate.severity,
                redacted: aggregate.redacted,
                locations: aggregate.locations,
            })
            .collect();
        Self {
            unsafe_output: true,
            warning: UNSAFE_OUTPUT_WARNING,
            source: report.source,
            scanned_at: report.scanned_at,
            coverage: report.coverage,
            coverage_evaluation: report.coverage_evaluation,
            aggregates,
            total_findings: report.total_findings,
        }
    }

    pub fn write_json(&self, mut w: impl Write) -> std::io::Result<()> {
        let serialized =
            serde_json::to_string_pretty(self).expect("UnsafeReport always serializes");
        writeln!(w, "{serialized}")
    }

    pub fn write_human(&self, mut w: impl Write) -> std::io::Result<()> {
        writeln!(w, "!! {UNSAFE_OUTPUT_WARNING}")?;
        writeln!(w)?;
        writeln!(
            w,
            "clavenar-shadow-scanner :: source={}  scanned_at={}",
            self.source,
            self.scanned_at.to_rfc3339()
        )?;
        writeln!(
            w,
            "{} unique secret(s) across {} finding(s)",
            self.aggregates.len(),
            self.total_findings
        )?;
        write_human_coverage(&self.coverage, &self.coverage_evaluation, &mut w)?;
        writeln!(w)?;

        if self.aggregates.is_empty() {
            writeln!(w, "  no findings.")?;
            return Ok(());
        }

        for aggregate in &self.aggregates {
            writeln!(
                w,
                "[{}] {}  fp={}",
                aggregate.severity.as_str().to_uppercase(),
                aggregate.detector,
                aggregate.fingerprint
            )?;
            writeln!(w, "  secret: {}", aggregate.raw)?;
            writeln!(w, "  found in {} location(s):", aggregate.locations.len())?;
            let cap = 5;
            for location in aggregate.locations.iter().take(cap) {
                writeln!(w, "    - {}:{}", location.location, location.line)?;
            }
            if aggregate.locations.len() > cap {
                writeln!(
                    w,
                    "    … {} more (use --json for full list)",
                    aggregate.locations.len() - cap
                )?;
            }
            if let Some(first) = aggregate.locations.first()
                && let Some(context) = &first.context
            {
                writeln!(w, "  context (first hit):")?;
                for line in context.lines() {
                    writeln!(w, "    {line}")?;
                }
            }
            writeln!(w)?;
        }
        Ok(())
    }
}

fn write_human_coverage(
    coverage: &ScanCoverage,
    evaluation: &CoverageEvaluation,
    mut w: impl Write,
) -> std::io::Result<()> {
    if coverage.partial() {
        writeln!(
            w,
            "!! PARTIAL COVERAGE — status={} incomplete={}/{} ({:.2}%) max={:.2}% recommended_exit={}",
            evaluation.status.as_str(),
            evaluation.incomplete_objects,
            evaluation.attempted_objects,
            evaluation.incomplete_percent,
            evaluation.max_partial_percent,
            evaluation.recommended_exit_code
        )?;
    }
    writeln!(
        w,
        "coverage: scanned={} object(s)/{} byte(s)  skipped={}  errors={}  truncated={}  partial={}",
        coverage.objects_scanned(),
        coverage.bytes_scanned(),
        coverage.objects_skipped(),
        coverage.source_errors().len(),
        coverage.truncated(),
        coverage.partial()
    )?;
    writeln!(
        w,
        "coverage policy: status={} incomplete={}/{} ({:.2}%) max={:.2}% recommended_exit={}",
        evaluation.status.as_str(),
        evaluation.incomplete_objects,
        evaluation.attempted_objects,
        evaluation.incomplete_percent,
        evaluation.max_partial_percent,
        evaluation.recommended_exit_code
    )?;
    if !coverage.source_errors().is_empty() {
        writeln!(w, "source errors:")?;
        for error in coverage.source_errors().iter().take(5) {
            writeln!(w, "  - {:?} {}: {}", error.kind, error.item, error.message)?;
        }
        if coverage.source_errors().len() > 5 {
            writeln!(
                w,
                "  - … {} more (use --json for full list)",
                coverage.source_errors().len() - 5
            )?;
        }
    }
    Ok(())
}

/// Filter findings by minimum severity. `Severity::Critical` is the
/// most-severe and orders smallest under our `Ord` impl, so "≥ severity"
/// means "ord <= chosen" in our enum direction.
pub fn filter_by_min_severity(findings: Vec<Finding>, min: Severity) -> Vec<Finding> {
    findings.into_iter().filter(|f| f.severity <= min).collect()
}

pub fn filter_unsafe_by_min_severity(
    findings: Vec<UnsafeFinding>,
    min: Severity,
) -> Vec<UnsafeFinding> {
    findings
        .into_iter()
        .filter(|finding| finding.safe().severity <= min)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::{Severity, scan_text_unredacted};
    use crate::sources::{COVERAGE_FAILURE_EXIT_CODE, SourceError, SourceErrorKind};

    fn finding(detector: &str, sev: Severity, raw: &str, loc: &str, line: u32) -> Finding {
        Finding::from_match(detector.into(), sev, loc.into(), line, raw, None)
    }

    #[test]
    fn aggregates_dedupe_same_secret_across_locations() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let f1 = finding("anthropic_api_key", Severity::Critical, key, "a/.env", 1);
        let f2 = finding("anthropic_api_key", Severity::Critical, key, "b/.env", 7);
        let r = Report::from_findings("test", vec![f1, f2]);
        assert_eq!(r.aggregates.len(), 1);
        assert_eq!(r.aggregates[0].locations.len(), 2);
        assert_eq!(r.total_findings, 2);
    }

    #[test]
    fn json_output_omits_raw_when_redacted() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = Report::from_findings(
            "test",
            vec![finding(
                "anthropic_api_key",
                Severity::Critical,
                key,
                "a",
                1,
            )],
        );
        let mut buf = Vec::new();
        r.write_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(!s.contains(key), "raw secret leaked into redacted output");
        assert!(s.contains("redacted"));
    }

    #[test]
    fn typed_coverage_is_preserved_in_json_and_human_output() {
        let mut outcome = ScanOutcome::from_findings(Vec::<Finding>::new());
        outcome.record_scanned(17);
        outcome.record_skipped();
        outcome.record_error(SourceError::new(
            SourceErrorKind::Read,
            "synthetic/file",
            "permission denied",
        ));
        outcome.mark_truncated();
        let report = Report::from_outcome("test", outcome);

        let mut json = Vec::new();
        report.write_json(&mut json).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["coverage"]["objects_scanned"], 1);
        assert_eq!(value["coverage"]["bytes_scanned"], 17);
        assert_eq!(value["coverage"]["objects_skipped"], 1);
        assert_eq!(value["coverage"]["source_errors"][0]["kind"], "read");
        assert_eq!(value["coverage"]["truncated"], true);
        assert_eq!(value["coverage"]["partial"], true);
        assert_eq!(value["coverage_evaluation"]["status"], "truncated");
        assert_eq!(
            value["coverage_evaluation"]["recommended_exit_code"],
            COVERAGE_FAILURE_EXIT_CODE
        );

        let mut human = Vec::new();
        report.write_human(&mut human).unwrap();
        let human = String::from_utf8(human).unwrap();
        assert!(human.contains("scanned=1 object(s)/17 byte(s)"));
        assert!(human.contains("skipped=1  errors=1"));
        assert!(human.contains("truncated=true  partial=true"));
        assert!(human.contains("!! PARTIAL COVERAGE"));
        assert!(human.contains("status=truncated"));
        assert!(human.contains("synthetic/file: permission denied"));
    }

    #[test]
    fn unsafe_json_output_includes_raw_and_warning() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let r = UnsafeReport::from_findings("test", scan_text_unredacted(key, "a"));
        let mut buf = Vec::new();
        r.write_json(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains(key));
        assert!(s.contains("\"unsafe_output\": true"));
        assert!(s.contains(UNSAFE_OUTPUT_WARNING));
    }

    #[test]
    fn unsafe_report_preserves_typed_coverage() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let mut outcome = ScanOutcome::from_findings(scan_text_unredacted(key, "a"));
        outcome.record_scanned(key.len());
        let report = UnsafeReport::from_outcome("test", outcome);
        let mut json = Vec::new();
        report.write_json(&mut json).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["coverage"]["objects_scanned"], 1);
        assert_eq!(value["coverage"]["bytes_scanned"], key.len());
        assert_eq!(value["coverage"]["partial"], false);
        assert_eq!(value["coverage_evaluation"]["status"], "complete");
    }

    #[test]
    fn unsafe_report_preserves_coverage_failure_decision() {
        let key = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let mut outcome = ScanOutcome::from_findings(scan_text_unredacted(key, "a"));
        outcome.record_scanned(key.len());
        outcome.record_skipped();
        let report = UnsafeReport::from_outcome_with_threshold("test", outcome, 10.0);
        let mut json = Vec::new();
        report.write_json(&mut json).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(value["coverage_evaluation"]["status"], "threshold_exceeded");
        assert_eq!(
            value["coverage_evaluation"]["recommended_exit_code"],
            COVERAGE_FAILURE_EXIT_CODE
        );
    }

    #[test]
    fn unsafe_human_output_includes_warning_banner() {
        let r = UnsafeReport::from_findings("test", vec![]);
        let mut buf = Vec::new();
        r.write_human(&mut buf).unwrap();
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
    fn aggregates_dedupe_same_location_across_detectors() {
        // Same physical hit reported by two detectors (vendor + generic
        // backstop on the same line) must collapse to one Location entry.
        // Without dedup the locations Vec inflates the "found in N
        // locations" count and breaks the README's "one entry, real
        // location count" contract.
        let key = "sk-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234";
        let f_vendor = finding("openai_api_key", Severity::Critical, key, "a/.env", 1);
        let f_generic = finding(
            "generic_high_entropy_secret",
            Severity::Medium,
            key,
            "a/.env",
            1,
        );
        let r = Report::from_findings("test", vec![f_vendor, f_generic]);
        assert_eq!(r.aggregates.len(), 1, "fingerprint dedupe broken");
        assert_eq!(
            r.aggregates[0].locations.len(),
            1,
            "same (location, line) must collapse to one entry"
        );
        // The vendor severity wins because it's the higher tier
        // (Critical < Medium under our inverted Ord).
        assert_eq!(r.aggregates[0].detector, "openai_api_key");
        assert_eq!(r.aggregates[0].severity, Severity::Critical);
    }

    #[test]
    fn aggregates_dedupe_does_not_collapse_distinct_lines() {
        let key = "sk-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234";
        // Same secret, same file, two different lines — must stay as two
        // distinct locations.
        let r = Report::from_findings(
            "test",
            vec![
                finding("openai_api_key", Severity::Critical, key, "a/.env", 1),
                finding("openai_api_key", Severity::Critical, key, "a/.env", 5),
            ],
        );
        assert_eq!(r.aggregates.len(), 1);
        assert_eq!(r.aggregates[0].locations.len(), 2);
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
        );
        // Critical entries lead, low last.
        assert_eq!(agg.aggregates[0].severity, Severity::Critical);
        assert_eq!(agg.aggregates.last().unwrap().severity, Severity::Low);
    }
}
