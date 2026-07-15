//! Per-platform fetchers. Every source feeds `(location, text)` pairs to the
//! [`crate::detector`] engine and returns the common typed coverage outcome.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

pub mod github;
pub mod local;
pub mod slack;

/// Stable source-stage classification for an item that could not be scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceErrorKind {
    Walk,
    Read,
    Repository,
    Tree,
    Blob,
    ConversationList,
    ChannelHistory,
}

/// Non-content error metadata carried into every report format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceError {
    pub kind: SourceErrorKind,
    pub item: String,
    pub message: String,
}

impl SourceError {
    pub fn new(kind: SourceErrorKind, item: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            item: item.into(),
            message: message.into(),
        }
    }
}

/// Coverage accounting shared by local, GitHub, and Slack sources.
///
/// Mutation stays private so `partial` cannot disagree with skips, errors, or
/// truncation. Library consumers get read-only accessors and serialized reports
/// expose the same fields directly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanCoverage {
    objects_scanned: u64,
    bytes_scanned: u64,
    objects_skipped: u64,
    source_errors: Vec<SourceError>,
    truncated: bool,
    partial: bool,
}

#[derive(Deserialize)]
struct ScanCoverageWire {
    #[serde(default)]
    objects_scanned: u64,
    #[serde(default)]
    bytes_scanned: u64,
    #[serde(default)]
    objects_skipped: u64,
    #[serde(default)]
    source_errors: Vec<SourceError>,
    #[serde(default)]
    truncated: bool,
    #[serde(default)]
    partial: bool,
}

impl<'de> Deserialize<'de> for ScanCoverage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ScanCoverageWire::deserialize(deserializer)?;
        let expected_partial =
            wire.objects_skipped > 0 || !wire.source_errors.is_empty() || wire.truncated;
        if wire.partial != expected_partial {
            return Err(D::Error::custom(
                "coverage partial state disagrees with skips, errors, or truncation",
            ));
        }
        Ok(Self {
            objects_scanned: wire.objects_scanned,
            bytes_scanned: wire.bytes_scanned,
            objects_skipped: wire.objects_skipped,
            source_errors: wire.source_errors,
            truncated: wire.truncated,
            partial: wire.partial,
        })
    }
}

impl ScanCoverage {
    pub fn objects_scanned(&self) -> u64 {
        self.objects_scanned
    }

    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }

    pub fn objects_skipped(&self) -> u64 {
        self.objects_skipped
    }

    pub fn source_errors(&self) -> &[SourceError] {
        &self.source_errors
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn partial(&self) -> bool {
        self.partial
    }

    fn record_scanned(&mut self, bytes: usize) {
        self.objects_scanned = self.objects_scanned.saturating_add(1);
        self.bytes_scanned = self.bytes_scanned.saturating_add(bytes as u64);
    }

    fn record_skipped(&mut self) {
        self.objects_skipped = self.objects_skipped.saturating_add(1);
        self.partial = true;
    }

    fn record_error(&mut self, error: SourceError) {
        self.source_errors.push(error);
        self.partial = true;
    }

    fn mark_truncated(&mut self) {
        self.truncated = true;
        self.partial = true;
    }

    fn merge(&mut self, other: Self) {
        self.objects_scanned = self.objects_scanned.saturating_add(other.objects_scanned);
        self.bytes_scanned = self.bytes_scanned.saturating_add(other.bytes_scanned);
        self.objects_skipped = self.objects_skipped.saturating_add(other.objects_skipped);
        self.source_errors.extend(other.source_errors);
        self.truncated |= other.truncated;
        self.partial |= other.partial;
    }
}

/// Typed result from a source scan. Safe and explicit-unsafe finding types use
/// the same coverage contract without sharing their secret-bearing models.
#[derive(Debug, Clone)]
pub struct ScanOutcome<F> {
    pub findings: Vec<F>,
    coverage: ScanCoverage,
}

impl<F> Default for ScanOutcome<F> {
    fn default() -> Self {
        Self {
            findings: Vec::new(),
            coverage: ScanCoverage::default(),
        }
    }
}

impl<F> ScanOutcome<F> {
    pub fn from_findings(findings: Vec<F>) -> Self {
        Self {
            findings,
            coverage: ScanCoverage::default(),
        }
    }

    pub fn coverage(&self) -> &ScanCoverage {
        &self.coverage
    }

    pub fn record_scanned(&mut self, bytes: usize) {
        self.coverage.record_scanned(bytes);
    }

    pub fn record_skipped(&mut self) {
        self.coverage.record_skipped();
    }

    pub fn record_error(&mut self, error: SourceError) {
        self.coverage.record_error(error);
    }

    pub fn mark_truncated(&mut self) {
        self.coverage.mark_truncated();
    }

    pub fn append_findings(&mut self, findings: &mut Vec<F>) {
        self.findings.append(findings);
    }

    pub fn merge(&mut self, mut other: Self) {
        self.findings.append(&mut other.findings);
        self.coverage.merge(other.coverage);
    }

    pub fn map_findings<G>(self, map: impl FnOnce(Vec<F>) -> Vec<G>) -> ScanOutcome<G> {
        ScanOutcome {
            findings: map(self.findings),
            coverage: self.coverage,
        }
    }

    pub fn into_parts(self) -> (Vec<F>, ScanCoverage) {
        (self.findings, self.coverage)
    }
}

/// Cap on individual file size, in bytes. 1 MiB covers virtually every
/// hand-edited config / source file; anything bigger is almost certainly
/// generated (lockfiles, minified bundles, fixtures) and not worth the
/// regex time.
pub(crate) const MAX_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) const USER_AGENT_VALUE: &str = "clavenar-shadow-scanner/0.1";

/// `git`-style binary detection: any NUL byte in the first 8 KiB means
/// "treat as binary." UTF-8 can't contain NUL, so a positive hit rules
/// out source code.
pub(crate) fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_outcome_starts_complete() {
        let mut outcome = ScanOutcome::<()>::default();
        outcome.record_scanned(7);
        assert_eq!(outcome.coverage().objects_scanned(), 1);
        assert_eq!(outcome.coverage().bytes_scanned(), 7);
        assert!(!outcome.coverage().partial());
    }

    #[test]
    fn every_incomplete_signal_sets_partial() {
        let mut skipped = ScanOutcome::<()>::default();
        skipped.record_skipped();
        assert!(skipped.coverage().partial());

        let mut errored = ScanOutcome::<()>::default();
        errored.record_error(SourceError::new(
            SourceErrorKind::Read,
            "fixture",
            "unavailable",
        ));
        assert!(errored.coverage().partial());

        let mut truncated = ScanOutcome::<()>::default();
        truncated.mark_truncated();
        assert!(truncated.coverage().partial());
    }

    #[test]
    fn merge_preserves_findings_and_coverage() {
        let mut left = ScanOutcome::from_findings(vec![1]);
        left.record_scanned(4);
        let mut right = ScanOutcome::from_findings(vec![2]);
        right.record_skipped();
        right.record_error(SourceError::new(
            SourceErrorKind::Blob,
            "repo:file",
            "unavailable",
        ));
        left.merge(right);

        assert_eq!(left.findings, vec![1, 2]);
        assert_eq!(left.coverage().objects_scanned(), 1);
        assert_eq!(left.coverage().objects_skipped(), 1);
        assert_eq!(left.coverage().source_errors().len(), 1);
        assert!(left.coverage().partial());
    }

    #[test]
    fn deserialization_rejects_inconsistent_partial_state() {
        let result = serde_json::from_str::<ScanCoverage>(
            r#"{"objects_scanned":0,"bytes_scanned":0,"objects_skipped":1,"source_errors":[],"truncated":false,"partial":false}"#,
        );
        assert!(result.is_err());
    }
}
