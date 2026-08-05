//! Per-platform fetchers. Every source feeds `(location, text)` pairs to the
//! [`crate::detector`] engine and returns the common typed coverage outcome.

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::collections::BTreeMap;

pub mod github;
pub mod local;
pub mod slack;

pub const DEFAULT_MAX_PARTIAL_PERCENT: f64 = 10.0;
pub const COVERAGE_FAILURE_EXIT_CODE: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Complete,
    PartialWithinThreshold,
    ThresholdExceeded,
    Truncated,
    TotalFailure,
}

impl CoverageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::PartialWithinThreshold => "partial_within_threshold",
            Self::ThresholdExceeded => "threshold_exceeded",
            Self::Truncated => "truncated",
            Self::TotalFailure => "total_failure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoverageEvaluation {
    pub status: CoverageStatus,
    pub attempted_objects: u64,
    pub incomplete_objects: u64,
    pub incomplete_percent: f64,
    pub max_partial_percent: f64,
    pub recommended_exit_code: i32,
}

impl CoverageEvaluation {
    pub fn evaluate(coverage: &ScanCoverage, max_partial_percent: f64) -> Self {
        let max_partial_percent =
            if max_partial_percent.is_finite() && (0.0..=100.0).contains(&max_partial_percent) {
                max_partial_percent
            } else {
                0.0
            };
        let error_count = coverage.source_errors.len() as u64;
        let incomplete_objects = coverage.objects_skipped.saturating_add(error_count);
        let attempted_objects = coverage.objects_scanned.saturating_add(incomplete_objects);
        let incomplete_percent = if attempted_objects == 0 {
            0.0
        } else {
            incomplete_objects as f64 / attempted_objects as f64 * 100.0
        };
        let status = if !coverage.partial {
            CoverageStatus::Complete
        } else if coverage.truncated {
            CoverageStatus::Truncated
        } else if coverage.objects_scanned == 0 {
            CoverageStatus::TotalFailure
        } else if incomplete_percent > max_partial_percent {
            CoverageStatus::ThresholdExceeded
        } else {
            CoverageStatus::PartialWithinThreshold
        };
        let recommended_exit_code = if matches!(
            status,
            CoverageStatus::ThresholdExceeded
                | CoverageStatus::Truncated
                | CoverageStatus::TotalFailure
        ) {
            COVERAGE_FAILURE_EXIT_CODE
        } else {
            0
        };
        Self {
            status,
            attempted_objects,
            incomplete_objects,
            incomplete_percent,
            max_partial_percent,
            recommended_exit_code,
        }
    }

    pub fn requires_failure(&self) -> bool {
        self.recommended_exit_code == COVERAGE_FAILURE_EXIT_CODE
    }
}

impl Default for CoverageEvaluation {
    fn default() -> Self {
        Self::evaluate(&ScanCoverage::default(), DEFAULT_MAX_PARTIAL_PERCENT)
    }
}

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
            item: truncate_metadata(item.into(), MAX_SOURCE_ITEM_BYTES),
            message: truncate_metadata(message.into(), MAX_SOURCE_MESSAGE_BYTES),
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
    objects_excluded: u64,
    exclusion_reasons: BTreeMap<String, u64>,
    scope: Vec<String>,
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
    objects_excluded: u64,
    #[serde(default)]
    exclusion_reasons: BTreeMap<String, u64>,
    #[serde(default)]
    scope: Vec<String>,
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
        let excluded_total = wire
            .exclusion_reasons
            .values()
            .fold(0_u64, |total, count| total.saturating_add(*count));
        if excluded_total != wire.objects_excluded {
            return Err(D::Error::custom(
                "coverage exclusion count disagrees with exclusion reasons",
            ));
        }
        Ok(Self {
            objects_scanned: wire.objects_scanned,
            bytes_scanned: wire.bytes_scanned,
            objects_skipped: wire.objects_skipped,
            objects_excluded: wire.objects_excluded,
            exclusion_reasons: wire.exclusion_reasons,
            scope: wire.scope,
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

    pub fn objects_excluded(&self) -> u64 {
        self.objects_excluded
    }

    pub fn exclusion_reasons(&self) -> &BTreeMap<String, u64> {
        &self.exclusion_reasons
    }

    pub fn scope(&self) -> &[String] {
        &self.scope
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

    fn record_excluded(&mut self, reason: impl Into<String>) {
        self.objects_excluded = self.objects_excluded.saturating_add(1);
        let mut reason = truncate_metadata(reason.into(), MAX_SOURCE_ITEM_BYTES);
        if self.exclusion_reasons.len() >= MAX_EXCLUSION_REASONS.saturating_sub(1)
            && !self.exclusion_reasons.contains_key(&reason)
        {
            reason = "other".to_string();
        }
        let count = self.exclusion_reasons.entry(reason).or_default();
        *count = count.saturating_add(1);
    }

    fn record_scope(&mut self, scope: impl Into<String>) {
        let scope = truncate_metadata(scope.into(), MAX_SOURCE_ITEM_BYTES);
        if self.scope.len() < MAX_SCOPE_ENTRIES && !self.scope.contains(&scope) {
            self.scope.push(scope);
        }
    }

    fn record_error(&mut self, error: SourceError) {
        if self.source_errors.len() < MAX_SOURCE_ERRORS {
            self.source_errors.push(error);
        } else {
            self.truncated = true;
        }
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
        self.objects_excluded = self.objects_excluded.saturating_add(other.objects_excluded);
        for (mut reason, count) in other.exclusion_reasons {
            if self.exclusion_reasons.len() >= MAX_EXCLUSION_REASONS.saturating_sub(1)
                && !self.exclusion_reasons.contains_key(&reason)
            {
                reason = "other".to_string();
            }
            let current = self.exclusion_reasons.entry(reason).or_default();
            *current = current.saturating_add(count);
        }
        for scope in other.scope {
            self.record_scope(scope);
        }
        for error in other.source_errors {
            self.record_error(error);
        }
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
        let mut outcome = Self::default();
        let mut findings = findings;
        outcome.append_findings(&mut findings);
        outcome
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

    /// Record an object intentionally outside the configured scan scope.
    /// Exclusions are observable but do not make otherwise-complete coverage
    /// partial.
    pub fn record_excluded(&mut self, reason: impl Into<String>) {
        self.coverage.record_excluded(reason);
    }

    /// Describe the configured source scope in serialized coverage metadata.
    pub fn record_scope(&mut self, scope: impl Into<String>) {
        self.coverage.record_scope(scope);
    }

    pub fn record_error(&mut self, error: SourceError) {
        self.coverage.record_error(error);
    }

    pub fn mark_truncated(&mut self) {
        self.coverage.mark_truncated();
    }

    pub fn append_findings(&mut self, findings: &mut Vec<F>) {
        let remaining = MAX_FINDINGS.saturating_sub(self.findings.len());
        if findings.len() > remaining {
            findings.truncate(remaining);
            self.coverage.mark_truncated();
        }
        self.findings.append(findings);
    }

    pub fn merge(&mut self, mut other: Self) {
        self.append_findings(&mut other.findings);
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

pub(crate) const MAX_REMOTE_BODY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_SOURCE_OBJECTS: usize = 100_000;
const MAX_FINDINGS: usize = 100_000;
const MAX_SOURCE_ERRORS: usize = 10_000;
const MAX_SOURCE_ITEM_BYTES: usize = 1024;
const MAX_SOURCE_MESSAGE_BYTES: usize = 2048;
const MAX_SCOPE_ENTRIES: usize = 32;
const MAX_EXCLUSION_REASONS: usize = 64;

pub(crate) const USER_AGENT_VALUE: &str =
    concat!("clavenar-shadow-scanner/", env!("CARGO_PKG_VERSION"));

fn truncate_metadata(mut value: String, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes.saturating_sub('…'.len_utf8());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value.push('…');
    value
}

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
    fn intentional_exclusions_are_visible_but_not_partial() {
        let mut outcome = ScanOutcome::<()>::default();
        outcome.record_scope("github:default_branch_non_archived_non_fork");
        outcome.record_excluded("archived_repository");
        outcome.record_excluded("archived_repository");

        assert_eq!(outcome.coverage().objects_excluded(), 2);
        assert_eq!(
            outcome.coverage().exclusion_reasons()["archived_repository"],
            2
        );
        assert_eq!(outcome.coverage().scope().len(), 1);
        assert!(!outcome.coverage().partial());
        assert_eq!(
            CoverageEvaluation::evaluate(outcome.coverage(), 0.0).status,
            CoverageStatus::Complete
        );
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

    #[test]
    fn deserialization_rejects_inconsistent_exclusion_totals() {
        let result = serde_json::from_str::<ScanCoverage>(
            r#"{"objects_scanned":0,"bytes_scanned":0,"objects_skipped":0,"objects_excluded":2,"exclusion_reasons":{"binary_file":1},"source_errors":[],"truncated":false,"partial":false}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn source_error_metadata_is_utf8_safely_bounded() {
        let error = SourceError::new(
            SourceErrorKind::Read,
            "π".repeat(MAX_SOURCE_ITEM_BYTES),
            "λ".repeat(MAX_SOURCE_MESSAGE_BYTES),
        );
        assert!(error.item.len() <= MAX_SOURCE_ITEM_BYTES);
        assert!(error.message.len() <= MAX_SOURCE_MESSAGE_BYTES);
        assert!(error.item.ends_with('…'));
        assert!(error.message.ends_with('…'));
    }

    #[test]
    fn coverage_policy_is_strictly_above_threshold() {
        let mut outcome = ScanOutcome::<()>::default();
        for _ in 0..9 {
            outcome.record_scanned(1);
        }
        outcome.record_skipped();
        let at_threshold = CoverageEvaluation::evaluate(outcome.coverage(), 10.0);
        assert_eq!(at_threshold.status, CoverageStatus::PartialWithinThreshold);
        assert_eq!(at_threshold.incomplete_percent, 10.0);
        assert!(!at_threshold.requires_failure());

        let above_threshold = CoverageEvaluation::evaluate(outcome.coverage(), 9.9);
        assert_eq!(above_threshold.status, CoverageStatus::ThresholdExceeded);
        assert!(above_threshold.requires_failure());
    }

    #[test]
    fn total_failure_and_truncation_always_fail() {
        let mut total = ScanOutcome::<()>::default();
        total.record_error(SourceError::new(
            SourceErrorKind::Read,
            "fixture",
            "unavailable",
        ));
        let total = CoverageEvaluation::evaluate(total.coverage(), 100.0);
        assert_eq!(total.status, CoverageStatus::TotalFailure);
        assert!(total.requires_failure());

        let mut truncated = ScanOutcome::<()>::default();
        truncated.mark_truncated();
        let truncated = CoverageEvaluation::evaluate(truncated.coverage(), 100.0);
        assert_eq!(truncated.status, CoverageStatus::Truncated);
        assert!(truncated.requires_failure());
    }

    #[test]
    fn invalid_library_threshold_fails_closed_to_zero() {
        let mut outcome = ScanOutcome::<()>::default();
        outcome.record_scanned(1);
        outcome.record_skipped();
        let evaluation = CoverageEvaluation::evaluate(outcome.coverage(), f64::NAN);
        assert_eq!(evaluation.max_partial_percent, 0.0);
        assert_eq!(evaluation.status, CoverageStatus::ThresholdExceeded);
    }
}
