//! Clavenar — shadow scanner.
//!
//! A free top-of-funnel discovery tool that scans GitHub orgs, Slack
//! channels, and local filesystems for unauthorized agent credentials
//! (AI provider keys, cloud keys, dev-platform tokens). The point is to
//! tell an organization what secrets are *already* in places they
//! shouldn't be, before someone else does.
//!
//! ## Layout
//!
//! * [`detector`] — credential pattern engine + ruleset.
//! * [`sources`] — per-platform fetchers. Each source produces a
//!   stream of `(location, text)` pairs that the engine scans.
//! * [`output`] — JSON / human formatters with default redaction.
//!
//! Library consumers (tests, future SDK) talk to [`scan_text`] and the
//! source modules directly. The CLI in `main.rs` is a thin wrapper.

pub mod detector;
pub mod output;
pub mod sources;

pub use detector::{
    Detector, Finding, Severity, UnsafeFinding, detectors, redact, scan_text, scan_text_unredacted,
    shannon_entropy,
};
pub use sources::local::LocalScanMode;
pub use sources::{
    COVERAGE_FAILURE_EXIT_CODE, CoverageEvaluation, CoverageStatus, DEFAULT_MAX_PARTIAL_PERCENT,
    ScanCoverage, ScanOutcome, SourceError, SourceErrorKind,
};
