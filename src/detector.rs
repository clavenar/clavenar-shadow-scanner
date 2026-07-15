//! Credential pattern detectors and the engine that drives them.
//!
//! Each [`Detector`] is a regex with metadata. The engine walks an input
//! string line-by-line and yields a [`Finding`] for every match. The two
//! detector flavours are:
//!
//! 1. **Vendor-specific** patterns — Anthropic `sk-ant-…`, OpenAI `sk-…`,
//!    AWS `AKIA…`, GitHub `gh[opsu]_…`, Slack `xox[abprs]-…`, etc. These
//!    are high-precision: a match is almost certainly a real key.
//! 2. **Generic high-entropy** — long base64-ish strings near keywords
//!    like `key`, `token`, `secret`. Lower precision; useful as a
//!    backstop for vendors we don't have explicit detectors for.
//!
//! ## Output safety
//!
//! [`Finding`] is safe by construction: it stores only a fingerprint,
//! redacted display value, and redacted context. The default scan path drops
//! matched plaintext before returning. Raw values exist only in the explicitly
//! named [`UnsafeFinding`] returned by [`scan_text_unredacted`], which the CLI
//! exposes for local scans only.
//!
//! Generic-detector entropy floor is 4.0 bits/byte: random base64 lands
//! 4.5–5.5, English prose ~4.0, so 4.0 + a length floor keeps short
//! identifiers from tripping the catch-all rule.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{ops::Range, sync::OnceLock};

const MAX_SCANNED_LINE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Almost certainly a live credential — high-precision vendor match.
    Critical,
    /// Probable credential — vendor pattern with weaker anchors.
    High,
    /// Possible credential — generic high-entropy near a sensitive keyword.
    Medium,
    /// Suspicious; surfaced for review.
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
    pub fn from_min(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(Severity::Critical),
            "high" => Some(Severity::High),
            "medium" => Some(Severity::Medium),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    pub severity: Severity,
    /// Where the match came from. Source-specific: a path for local-fs,
    /// `owner/repo:path@ref` for GitHub, `slack://channel/ts` for Slack.
    pub location: String,
    pub line: u32,
    /// Stable SHA-256-derived identifier used for deduplication.
    pub fingerprint: String,
    /// Non-recoverable display form (`<first 4>…<last 4>` for long values).
    pub redacted: String,
    /// ±2 lines of source context, with the secret already redacted in
    /// place. Safe to display.
    pub context: Option<String>,
}

impl Finding {
    pub(crate) fn from_match(
        detector: String,
        severity: Severity,
        location: String,
        line: u32,
        raw_match: &str,
        context: Option<String>,
    ) -> Self {
        Self {
            detector,
            severity,
            location,
            line,
            fingerprint: fingerprint(raw_match),
            redacted: redact(raw_match),
            context,
        }
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn redacted(&self) -> &str {
        &self.redacted
    }
}

/// A finding that deliberately retains matched plaintext for explicit local
/// unsafe output. It is intentionally not serializable and its `Debug`
/// implementation delegates to the safe finding so logs cannot expose raw
/// material accidentally.
#[derive(Clone)]
pub struct UnsafeFinding {
    safe: Finding,
    raw_match: String,
}

impl std::fmt::Debug for UnsafeFinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnsafeFinding")
            .field("safe", &self.safe)
            .field("raw_match", &"<redacted>")
            .finish()
    }
}

impl UnsafeFinding {
    pub fn safe(&self) -> &Finding {
        &self.safe
    }

    pub fn raw_secret(&self) -> &str {
        &self.raw_match
    }

    pub fn into_safe(self) -> Finding {
        self.safe
    }

    pub(crate) fn into_parts(self) -> (Finding, String) {
        (self.safe, self.raw_match)
    }
}

fn fingerprint(raw_match: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(raw_match.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

pub fn redact(s: &str) -> String {
    let n = s.chars().count();
    if n <= 12 {
        return "<redacted>".to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[n - 4..].iter().collect();
    format!("{}…{}", head, tail)
}

#[derive(Debug, Clone)]
pub struct Detector {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    /// Regex over a single line of source. If a capture group is
    /// present, group 1 is the secret; otherwise the whole match is.
    pub pattern: Regex,
    /// Optional Shannon-entropy floor (bits/byte). When set, the
    /// matched secret must clear this to fire. Used by the generic
    /// detector to suppress identifiers that look pattern-shaped but
    /// are deterministic words.
    pub min_entropy: Option<f64>,
    /// Optional minimum length (chars) for the matched secret.
    pub min_length: Option<usize>,
}

/// Process-wide detector list, built lazily on first call.
pub fn detectors() -> &'static [Detector] {
    static DETECTORS: OnceLock<Vec<Detector>> = OnceLock::new();
    DETECTORS.get_or_init(build_detectors)
}

fn r(s: &str) -> Regex {
    Regex::new(s).expect("static detector regex should compile")
}

// Declarative table — each `Detector` is a short, uniform struct literal.
// `too_many_lines` punishes the density a catalog wants; suppression is
// the documented use-case for declarative builders.
#[allow(clippy::too_many_lines)]
fn build_detectors() -> Vec<Detector> {
    vec![
        // --- AI provider keys ---------------------------------------------------
        Detector {
            name: "anthropic_api_key",
            description: "Anthropic API key (sk-ant-...).",
            severity: Severity::Critical,
            pattern: r(r"\b(sk-ant-(?:api|admin)\d{2,}-[A-Za-z0-9_-]{32,})"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "openai_api_key",
            description: "OpenAI API key (sk-...).",
            severity: Severity::Critical,
            // OpenAI keys: sk-..., sk-proj-..., sk-svcacct-..., sk-admin-...
            pattern: r(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,})"),
            min_entropy: Some(3.5),
            min_length: Some(20),
        },
        Detector {
            name: "voyage_api_key",
            description: "Voyage AI API key (pa-...).",
            severity: Severity::High,
            pattern: r(r"\b(pa-[A-Za-z0-9_-]{40,})"),
            min_entropy: Some(3.5),
            min_length: None,
        },
        Detector {
            name: "cohere_api_key",
            description: "Cohere API key.",
            severity: Severity::High,
            // Cohere keys are ~40 char base64ish strings; surface only when
            // a "cohere" identifier is on the line to keep precision up.
            pattern: r(r#"(?i)cohere[^"'\n]{0,40}["']?([A-Za-z0-9]{40})\b"#),
            min_entropy: Some(3.5),
            min_length: Some(40),
        },
        Detector {
            name: "mistral_api_key",
            description: "Mistral API key.",
            severity: Severity::High,
            pattern: r(r#"(?i)mistral[^"'\n]{0,40}["']?([A-Za-z0-9]{32,40})\b"#),
            min_entropy: Some(3.5),
            min_length: Some(32),
        },
        Detector {
            name: "google_ai_api_key",
            description: "Google AI / Gemini API key (AIza...).",
            severity: Severity::Critical,
            pattern: r(r"\b(AIza[A-Za-z0-9_-]{35})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "xai_api_key",
            description: "xAI / Grok API key (xai-...).",
            severity: Severity::Critical,
            pattern: r(r"\b(xai-[A-Za-z0-9]{80})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "groq_api_key",
            description: "Groq API key (gsk_...).",
            severity: Severity::Critical,
            pattern: r(r"\b(gsk_[A-Za-z0-9]{52})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "huggingface_token",
            description: "Hugging Face user / OAuth access token (hf_...).",
            severity: Severity::Critical,
            // HF user-access tokens are `hf_` + 34-40 alphanum. OAuth-issued
            // tokens use the same prefix but typically run longer; the {30,}
            // floor covers both without admitting short identifiers.
            pattern: r(r"\b(hf_[A-Za-z0-9]{30,})\b"),
            min_entropy: None,
            min_length: None,
        },
        // --- Cloud provider keys -----------------------------------------------
        Detector {
            name: "aws_access_key_id",
            description: "AWS access key ID (AKIA / ASIA / AGPA).",
            severity: Severity::Critical,
            pattern: r(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[A-Z0-9]{16})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "aws_secret_access_key",
            description: "AWS secret access key (40 char b64ish near 'aws').",
            severity: Severity::Critical,
            pattern: r(
                r#"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[^"'\n]{0,20}["']?([A-Za-z0-9/+=]{40})\b"#,
            ),
            min_entropy: Some(4.0),
            min_length: Some(40),
        },
        Detector {
            name: "gcp_service_account_key",
            description: "Google Cloud service-account private-key JSON marker.",
            severity: Severity::Critical,
            pattern: r(r#"("private_key_id"\s*:\s*"[a-f0-9]{40}")"#),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "azure_client_secret",
            description: "Azure AD client secret (high-entropy near AZURE_CLIENT_SECRET).",
            severity: Severity::High,
            pattern: r(
                r#"(?i)azure[_\-]?client[_\-]?secret[^"'\n]{0,20}["']?([A-Za-z0-9~._\-]{34,})"#,
            ),
            min_entropy: Some(4.0),
            min_length: Some(34),
        },
        Detector {
            name: "cloudflare_api_token",
            description: "Cloudflare API token (40-char base64ish, anchored near 'cloudflare').",
            severity: Severity::High,
            // Modern user API tokens have no fixed prefix; anchor on the
            // 'cloudflare' / 'cf_api_token' keyword to keep precision up.
            pattern: r(
                r#"(?i)(?:cloudflare|cf[_-]?api[_-]?token)[^"'\n]{0,20}["']?([A-Za-z0-9_\-]{40})\b"#,
            ),
            min_entropy: Some(4.0),
            min_length: Some(40),
        },
        Detector {
            name: "digitalocean_pat",
            description: "DigitalOcean personal access token (dop_v1_...).",
            severity: Severity::Critical,
            pattern: r(r"\b(dop_v1_[a-f0-9]{64})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "fly_io_token",
            description: "Fly.io macaroon token (FlyV1 fm[12]_...).",
            severity: Severity::High,
            // Fly emits macaroons prefixed with `FlyV1 fm2_` (current) or
            // `fm1_` (legacy); the body is a base64 payload. Anchoring on
            // the `FlyV1 fm` shape eliminates collisions with bare `fm_`
            // strings that appear in unrelated codebases.
            pattern: r(r"\b(FlyV1 fm[12]_[A-Za-z0-9+/=_\-]{40,})"),
            min_entropy: None,
            min_length: None,
        },
        // --- Developer-platform tokens -----------------------------------------
        Detector {
            name: "github_pat",
            description: "GitHub personal access / fine-grained / OAuth / App installation token.",
            severity: Severity::Critical,
            // Covers ghp_ (classic PAT), gho_ (OAuth), ghu_ (user-to-server),
            // ghs_ (server-to-server / App installation), ghr_ (refresh).
            pattern: r(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "slack_bot_token",
            description: "Slack bot/user/app token (xoxb / xoxp / xoxa / xoxs / xoxr).",
            severity: Severity::Critical,
            pattern: r(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "slack_webhook_url",
            description: "Slack incoming webhook URL.",
            severity: Severity::High,
            pattern: r(
                r"(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
            ),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "stripe_live_key",
            description: "Stripe live secret/restricted key.",
            severity: Severity::Critical,
            pattern: r(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "stripe_test_key",
            description: "Stripe test secret/restricted key.",
            severity: Severity::Low,
            pattern: r(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "private_key_pem",
            description: "PEM-armoured private key block.",
            severity: Severity::Critical,
            pattern: r(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "jwt_token",
            description: "JWT (header.payload.signature, base64url).",
            severity: Severity::Medium,
            pattern: r(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "npm_token",
            description: "NPM access token.",
            severity: Severity::High,
            pattern: r(r"\b(npm_[A-Za-z0-9]{36})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "gitlab_pat",
            description: "GitLab personal access token (glpat-...).",
            severity: Severity::High,
            pattern: r(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "atlassian_api_token",
            description: "Atlassian API token (ATATT3xFfGF0...) used by Jira / Confluence / Bitbucket Cloud.",
            severity: Severity::High,
            pattern: r(r"\b(ATATT3[A-Za-z0-9_\-]{50,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "sourcegraph_pat",
            description: "Sourcegraph personal access token (sgp_...).",
            severity: Severity::Medium,
            pattern: r(r"\b(sgp_[A-Za-z0-9]{40,})\b"),
            min_entropy: None,
            min_length: None,
        },
        // --- CI / deploy platforms ---------------------------------------------
        Detector {
            name: "vercel_token",
            description: "Vercel access token (24-char alphanum, anchored near 'vercel').",
            severity: Severity::High,
            pattern: r(r#"(?i)vercel[^"'\n]{0,40}["']?([A-Za-z0-9]{24})\b"#),
            min_entropy: Some(4.0),
            min_length: Some(24),
        },
        Detector {
            name: "netlify_pat",
            description: "Netlify personal access token (nfp_...).",
            severity: Severity::High,
            pattern: r(r"\b(nfp_[A-Za-z0-9]{40,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "railway_token",
            description: "Railway project / team token (UUID near 'railway').",
            severity: Severity::High,
            pattern: r(
                r#"(?i)railway[^"'\n]{0,40}["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b"#,
            ),
            min_entropy: None,
            min_length: None,
        },
        // --- Database / data plane ---------------------------------------------
        Detector {
            name: "planetscale_password",
            description: "PlanetScale database password (pscale_pw_...).",
            severity: Severity::Critical,
            pattern: r(r"\b(pscale_pw_[A-Za-z0-9_\-]{40,})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "supabase_service_role_jwt",
            description: "Supabase service-role JWT (admin-scope database key).",
            severity: Severity::Critical,
            // The JWT body decodes to `role:"service_role"` — we can't see
            // that without decoding, so anchor on a `supabase` identifier on
            // the same line + a JWT-shaped value to keep precision high.
            pattern: r(
                r#"(?i)supabase[^"'\n]{0,40}["']?(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"#,
            ),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "neon_postgres_url",
            description: "Neon Postgres connection URL with embedded password (...@*.neon.tech).",
            severity: Severity::Critical,
            pattern: r(r"(postgres(?:ql)?://[^\s:@]+:[^\s@]+@[^\s/]+\.neon\.tech[^\s]*)"),
            min_entropy: None,
            min_length: None,
        },
        // --- Communications / messaging ----------------------------------------
        Detector {
            name: "telegram_bot_token",
            description: "Telegram bot token (<bot_id>:<35-char body>).",
            severity: Severity::Medium,
            pattern: r(r"\b(\d{8,10}:[A-Za-z0-9_\-]{35})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "discord_bot_token",
            description: "Discord bot token (3-segment base64-dotted).",
            severity: Severity::Medium,
            // Bot tokens start with M/N (snowflake encoded), then `.`,
            // 6-7 char timestamp segment, `.`, 27-38 char HMAC tail.
            pattern: r(r"\b([MN][A-Za-z\d]{23,28}\.[\w\-]{6,7}\.[\w\-]{27,38})\b"),
            min_entropy: None,
            min_length: None,
        },
        Detector {
            name: "sendgrid_api_key",
            description: "SendGrid API key (SG.<22>.<43>).",
            severity: Severity::High,
            pattern: r(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
            min_entropy: None,
            min_length: None,
        },
        // --- Generic high-entropy near a sensitive keyword ---------------------
        Detector {
            name: "generic_high_entropy_secret",
            description: "Long high-entropy string near key/token/secret/api keyword.",
            severity: Severity::Medium,
            // Captures group 1: the candidate secret. Looks for an
            // identifier ending in key/token/secret/password followed by
            // `=` or `:` or whitespace, then a quoted-or-not 24+ char
            // base64ish string.
            pattern: r(
                r#"(?i)(?:api[_-]?key|access[_-]?token|secret(?:[_-]?key)?|auth[_-]?token|password|passwd|bearer)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{24,})["']?"#,
            ),
            min_entropy: Some(4.0),
            min_length: Some(24),
        },
    ]
}

/// Shannon entropy in bits/byte over `s`. Empty input → 0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    let mut h = 0.0f64;
    for c in counts.iter().filter(|&&c| c > 0) {
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    h
}

#[derive(Debug)]
struct SourceLine<'a> {
    content: &'a str,
    start: usize,
    end: usize,
}

#[derive(Debug)]
struct PendingFinding<'a> {
    detector: &'a Detector,
    line_idx: usize,
    span: Range<usize>,
    context_allowed: bool,
}

/// Run every detector against `text`, yielding findings keyed by
/// `location` + line. Locations are caller-supplied (path, repo
/// reference, message permalink — whatever's meaningful for the source).
///
/// Detection and rendering are deliberately separate passes. The first pass
/// records every accepted match as an absolute byte span. Only after all
/// detectors finish do we normalize those spans and render context with the
/// complete set redacted. This prevents one finding's context from exposing a
/// second credential on the same or a neighboring line.
pub fn scan_text(text: &str, location: &str) -> Vec<Finding> {
    scan_text_unredacted(text, location)
        .into_iter()
        .map(UnsafeFinding::into_safe)
        .collect()
}

/// Scan while deliberately retaining raw matched values. Callers must keep
/// this path local and visibly mark every output as secret-bearing.
pub fn scan_text_unredacted(text: &str, location: &str) -> Vec<UnsafeFinding> {
    let lines = source_lines(text);
    let mut pending = Vec::new();
    for (line_idx, line) in lines.iter().enumerate() {
        // Cheap pre-filter: skip lines longer than 4 KiB to avoid
        // pathological regex backtracking on minified bundles.
        if line.content.len() > MAX_SCANNED_LINE_BYTES {
            continue;
        }
        for det in detectors() {
            for caps in det.pattern.captures_iter(line.content) {
                let m = caps.get(1).or_else(|| caps.get(0));
                let matched = match m {
                    Some(m) => m,
                    None => continue,
                };
                let raw = matched.as_str();
                if let Some(min_len) = det.min_length
                    && raw.len() < min_len
                {
                    continue;
                }
                if let Some(min_h) = det.min_entropy
                    && shannon_entropy(raw) < min_h
                {
                    continue;
                }

                let match_span = (line.start + matched.start())..(line.start + matched.end());
                let (span, context_allowed) = if det.name == "private_key_pem" {
                    expand_pem_span(text, match_span)
                } else {
                    (match_span, true)
                };
                pending.push(PendingFinding {
                    detector: det,
                    line_idx,
                    span,
                    context_allowed,
                });
            }
        }
    }

    let redaction_spans = merge_spans(pending.iter().map(|finding| finding.span.clone()));
    pending
        .into_iter()
        .map(|finding| {
            let raw_match = &text[finding.span.clone()];
            let context = if finding.context_allowed {
                build_context(text, &lines, finding.line_idx, &redaction_spans)
            } else {
                None
            };
            UnsafeFinding {
                safe: Finding::from_match(
                    finding.detector.name.to_string(),
                    finding.detector.severity,
                    location.to_string(),
                    (finding.line_idx + 1) as u32,
                    raw_match,
                    context,
                ),
                raw_match: raw_match.to_string(),
            }
        })
        .collect()
}

fn source_lines(text: &str) -> Vec<SourceLine<'_>> {
    let mut offset = 0;
    text.split_inclusive('\n')
        .map(|raw_line| {
            let without_newline = raw_line.strip_suffix('\n').unwrap_or(raw_line);
            let content = without_newline
                .strip_suffix('\r')
                .unwrap_or(without_newline);
            let start = offset;
            let end = start + content.len();
            offset += raw_line.len();
            SourceLine {
                content,
                start,
                end,
            }
        })
        .collect()
}

/// Expand a PEM opener to its matching footer. An unterminated block is
/// treated as secret through EOF so it can redact neighboring contexts, but
/// its own context is omitted because the complete block boundary is unknown.
fn expand_pem_span(text: &str, opener: Range<usize>) -> (Range<usize>, bool) {
    let opener_text = &text[opener.clone()];
    let Some(label) = opener_text
        .strip_prefix("-----BEGIN ")
        .and_then(|value| value.strip_suffix("-----"))
    else {
        return (opener, false);
    };
    let footer = format!("-----END {label}-----");
    let Some(relative_end) = text[opener.end..].find(&footer) else {
        return (opener.start..text.len(), false);
    };
    (
        opener.start..(opener.end + relative_end + footer.len()),
        true,
    )
}

fn merge_spans(spans: impl IntoIterator<Item = Range<usize>>) -> Vec<Range<usize>> {
    let mut spans: Vec<_> = spans.into_iter().filter(|span| !span.is_empty()).collect();
    spans.sort_by_key(|span| (span.start, span.end));
    let mut merged: Vec<Range<usize>> = Vec::with_capacity(spans.len());
    for span in spans {
        if let Some(previous) = merged.last_mut()
            && span.start <= previous.end
        {
            previous.end = previous.end.max(span.end);
            continue;
        }
        merged.push(span);
    }
    merged
}

/// Build a 5-line redacted context window around `line_idx` (±2 lines).
/// Every detected span in the window is redacted. Context is omitted when the
/// window includes a line skipped by the detector size guard, because safe
/// rendering cannot then be proven.
fn build_context(
    text: &str,
    lines: &[SourceLine<'_>],
    line_idx: usize,
    redaction_spans: &[Range<usize>],
) -> Option<String> {
    let lo = line_idx.saturating_sub(2);
    let hi = (line_idx + 3).min(lines.len());
    if lines[lo..hi]
        .iter()
        .any(|line| line.content.len() > MAX_SCANNED_LINE_BYTES)
    {
        return None;
    }
    let mut out = String::new();
    for (i, line) in lines[lo..hi].iter().enumerate() {
        let n = lo + i + 1;
        let marker = if lo + i == line_idx { ">" } else { " " };
        let safe = render_redacted_line(text, line, redaction_spans)?;
        out.push_str(&format!("{} {:>4} | {}\n", marker, n, safe));
    }
    Some(out)
}

fn render_redacted_line(
    text: &str,
    line: &SourceLine<'_>,
    redaction_spans: &[Range<usize>],
) -> Option<String> {
    let mut cursor = line.start;
    let mut out = String::with_capacity(line.content.len());
    for span in redaction_spans {
        if span.end <= line.start {
            continue;
        }
        if span.start >= line.end {
            break;
        }
        let start = span.start.max(line.start);
        let end = span.end.min(line.end);
        if start < cursor || start > end {
            return None;
        }
        out.push_str(text.get(cursor..start)?);
        out.push_str(&redact(text.get(start..end)?));
        cursor = end;
    }
    out.push_str(text.get(cursor..line.end)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_short_string_says_redacted() {
        assert_eq!(redact("short"), "<redacted>");
        assert_eq!(redact("0123456789AB"), "<redacted>");
    }

    #[test]
    fn redact_long_string_keeps_edges() {
        assert_eq!(redact("0123456789ABCDEF"), "0123…CDEF");
    }

    #[test]
    fn shannon_entropy_zero_for_uniform_string() {
        assert_eq!(shannon_entropy(""), 0.0);
        // Single distinct character → 0 bits.
        assert!(shannon_entropy("aaaaaa") < 0.001);
    }

    #[test]
    fn shannon_entropy_higher_for_random_string() {
        // Random base64ish string clears 4.0 comfortably.
        let h = shannon_entropy("aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi");
        assert!(h > 4.0, "expected > 4.0, got {}", h);
    }

    #[test]
    fn detects_anthropic_key() {
        let text = r#"ANTHROPIC_API_KEY="sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW""#;
        let f = scan_text(text, "test");
        assert_eq!(f.len(), 1, "expected one finding, got {:?}", f);
        assert_eq!(f[0].detector, "anthropic_api_key");
        assert_eq!(f[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_openai_key() {
        // Synthetic high-entropy stand-in (mixed chars to clear the 3.5
        // bits/byte floor; the min_entropy filter would reject a pure
        // A-string of the same length).
        let text = r#"OPENAI_KEY = 'sk-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234'"#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "openai_api_key"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_aws_keypair() {
        let text = "
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "aws_access_key_id"));
        assert!(f.iter().any(|x| x.detector == "aws_secret_access_key"));
    }

    #[test]
    fn detects_github_pat() {
        let text = "token: ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "github_pat"));
    }

    #[test]
    fn github_pat_covers_all_token_prefixes() {
        // ghs_ used to have its own dedicated detector that overlapped
        // github_pat 1:1. After removing it, every prefix must still
        // resolve to a single github_pat finding (not zero, not two).
        for prefix in ["ghp", "gho", "ghu", "ghs", "ghr"] {
            let text = format!("token: {}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", prefix);
            let f = scan_text(&text, "test");
            let matches: Vec<_> = f.iter().filter(|x| x.detector == "github_pat").collect();
            assert_eq!(
                matches.len(),
                1,
                "{prefix}_ must produce exactly one github_pat finding: {f:?}"
            );
        }
    }

    #[test]
    fn detects_slack_bot_token() {
        let text = "SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmnop";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "slack_bot_token"));
    }

    #[test]
    fn detects_slack_webhook() {
        let text = "https://hooks.slack.com/services/T01ABCD/B02EFGH/abcdef1234567890";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "slack_webhook_url"));
    }

    #[test]
    fn detects_pem_private_key() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIE…\n";
        let f = scan_text(text, "test");
        assert!(f.iter().any(|x| x.detector == "private_key_pem"));
    }

    #[test]
    fn generic_high_entropy_only_fires_with_keyword() {
        // Without a "key/token/secret" keyword on the same line, a
        // long base64-ish string should NOT trip the generic detector.
        let plain = "let buffer = aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi;";
        let f = scan_text(plain, "test");
        assert!(
            !f.iter()
                .any(|x| x.detector == "generic_high_entropy_secret"),
            "false positive: {:?}",
            f
        );

        let with_kw = r#"api_key="aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi""#;
        let f2 = scan_text(with_kw, "test");
        assert!(
            f2.iter()
                .any(|x| x.detector == "generic_high_entropy_secret"),
            "missed real secret: {:?}",
            f2
        );
    }

    #[test]
    fn generic_detector_rejects_low_entropy_value() {
        // Looks like assignment, but the value is too low-entropy to be
        // a key (repeated chars).
        let text = r#"api_key="aaaaaaaaaaaaaaaaaaaaaaaaaa""#;
        let f = scan_text(text, "test");
        assert!(
            !f.iter()
                .any(|x| x.detector == "generic_high_entropy_secret")
        );
    }

    #[test]
    fn finding_fingerprint_is_stable_for_same_secret() {
        let mut t = String::from("anthropic = 'sk-ant-api03-AAAA");
        t.push_str(&"A".repeat(40));
        t.push('\'');
        let f1 = scan_text(&t, "loc-1");
        let f2 = scan_text(&t, "loc-2");
        assert_eq!(f1[0].fingerprint(), f2[0].fingerprint());
    }

    #[test]
    fn detects_xai_api_key() {
        // xAI keys are exactly `xai-` + 80 alphanum.
        let body: String = "aB3kQ9zL2pXn7rVfG8sJ".repeat(4); // 80 chars
        let text = format!("XAI_API_KEY=xai-{body}");
        let f = scan_text(&text, "test");
        assert!(
            f.iter().any(|x| x.detector == "xai_api_key"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_groq_api_key() {
        let text = "GROQ_API_KEY=gsk_aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234567890ABCDEFGHIJ";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "groq_api_key"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_huggingface_token() {
        let text = "HF_TOKEN=hf_aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "huggingface_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_cloudflare_api_token() {
        let text = r#"cloudflare_api_token = "aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi12345678""#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "cloudflare_api_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_digitalocean_pat() {
        let text =
            "DO_TOKEN=dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "digitalocean_pat"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_fly_io_token() {
        let text = "FLY_API_TOKEN=FlyV1 fm2_lJPECAAAAAAAAAAAAA+aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "fly_io_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_gitlab_pat() {
        let text = "GITLAB_TOKEN=glpat-aB3kQ9zL2pXn7rVfG8sJ";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "gitlab_pat"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_atlassian_api_token() {
        let text = "JIRA_TOKEN=ATATT3xFfGF0aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234567890AB";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "atlassian_api_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_sourcegraph_pat() {
        let text = "SRC_ACCESS_TOKEN=sgp_aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234ABCDEFG";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "sourcegraph_pat"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_vercel_token() {
        let text = r#"vercel_token = "aB3kQ9zL2pXn7rVfG8sJ4mTu""#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "vercel_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_netlify_pat() {
        // Netlify PATs are nfp_ + 40+ alphanum.
        let text = "NETLIFY_AUTH_TOKEN=nfp_aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi12345ABCDEFGH";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "netlify_pat"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_railway_token() {
        let text = r#"RAILWAY_TOKEN="abcd1234-ef56-7890-ab12-cdef34567890""#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "railway_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_planetscale_password() {
        let text = "DATABASE_URL=pscale_pw_aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234ABCDEFG";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "planetscale_password"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_supabase_service_role_jwt() {
        let text = r#"SUPABASE_SERVICE_ROLE_KEY="eyJhbGciOiJIUzI1NiIs.eyJzdWIxMjM0NTY3.aB3kQ9zL2pXn7rVfG8sJ""#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "supabase_service_role_jwt"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_neon_postgres_url() {
        let text = "DATABASE_URL=postgresql://user:supersecretpassword@ep-blue-dawn-12345.us-east-2.aws.neon.tech/mydb?sslmode=require";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "neon_postgres_url"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_telegram_bot_token() {
        // Telegram bot tokens: <bot_id>:<exactly 35 chars>.
        let text = r#"TELEGRAM_BOT_TOKEN="123456789:AAH-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcH""#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "telegram_bot_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_discord_bot_token() {
        let text =
            "DISCORD_BOT_TOKEN=MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.aB3kQ9.aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi";
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "discord_bot_token"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn detects_sendgrid_api_key() {
        // SendGrid: SG.<exactly 22>.<exactly 43>.
        let text = r#"SENDGRID_API_KEY="SG.aB3kQ9zL2pXn7rVfG8sJ4m.aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234567890A""#;
        let f = scan_text(text, "test");
        assert!(
            f.iter().any(|x| x.detector == "sendgrid_api_key"),
            "missed: {:?}",
            f
        );
    }

    #[test]
    fn context_window_redacts_secret_in_place() {
        let text =
            "before\nANTHROPIC_KEY=sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW\nafter";
        let f = scan_text(text, "test");
        let ctx = f[0].context.as_ref().unwrap();
        // Original secret must NOT appear in context (it should be redacted).
        assert!(!ctx.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        // Redaction marker should appear instead.
        assert!(ctx.contains("…"));
    }

    #[test]
    fn context_redacts_every_secret_on_the_same_line() {
        let anthropic = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-aZbYcXdW";
        let github = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let text = format!("ANTHROPIC={anthropic} GITHUB={github}");
        let findings = scan_text(&text, "same-line");
        assert!(findings.iter().any(|f| f.detector == "anthropic_api_key"));
        assert!(findings.iter().any(|f| f.detector == "github_pat"));
        for finding in findings {
            let context = finding.context.expect("safe context");
            assert!(!context.contains(anthropic));
            assert!(!context.contains(github));
        }
    }

    #[test]
    fn context_redacts_secrets_on_neighboring_lines() {
        let anthropic = "sk-ant-api03-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC-aZbYcXdW";
        let github = "ghp_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
        let text = format!("before\nA={anthropic}\nbetween\nG={github}\nafter");
        let findings = scan_text(&text, "neighboring-lines");
        assert_eq!(findings.len(), 2);
        for finding in findings {
            let context = finding.context.expect("safe context");
            assert!(!context.contains(anthropic));
            assert!(!context.contains(github));
        }
    }

    #[test]
    fn overlapping_detector_spans_merge_before_context_rendering() {
        let secret = "sk-aB3kQ9zL2pXn7rVfG8sJ4mTuYwDeRcHi1234";
        let text = format!("api_key=\"{secret}\"");
        let findings = scan_text(&text, "overlap");
        assert!(findings.iter().any(|f| f.detector == "openai_api_key"));
        assert!(
            findings
                .iter()
                .any(|f| f.detector == "generic_high_entropy_secret")
        );
        for finding in findings {
            let context = finding.context.expect("safe context");
            assert!(!context.contains(secret));
            assert_eq!(context.matches('…').count(), 1);
        }
    }

    #[test]
    fn complete_pem_block_is_one_span_and_fully_redacted_from_context() {
        let pem = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "MIIEpAIBAAKCAQEA7SyntheticPrivateKeyBodyLineOne\n",
            "SyntheticPrivateKeyBodyLineTwo9xYz\n",
            "-----END RSA PRIVATE KEY-----"
        );
        let findings = scan_text_unredacted(pem, "private.pem");
        let finding = findings
            .iter()
            .find(|f| f.safe().detector == "private_key_pem")
            .expect("PEM finding");
        assert_eq!(finding.raw_secret(), pem);
        let context = finding
            .safe()
            .context
            .as_ref()
            .expect("bounded PEM context");
        assert!(!context.contains("MIIEpAIBAAKCAQEA7SyntheticPrivateKeyBodyLineOne"));
        assert!(!context.contains("SyntheticPrivateKeyBodyLineTwo9xYz"));
        assert!(!context.contains("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn unterminated_pem_omits_its_context_and_redacts_neighbor_contexts() {
        let github = "ghp_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";
        let text = format!("-----BEGIN RSA PRIVATE KEY-----\nSyntheticBody\nnearby={github}\n");
        let findings = scan_text(&text, "unterminated.pem");
        let pem = findings
            .iter()
            .find(|f| f.detector == "private_key_pem")
            .expect("PEM finding");
        assert!(pem.context.is_none());
        let github_finding = findings
            .iter()
            .find(|f| f.detector == "github_pat")
            .expect("GitHub finding");
        let context = github_finding.context.as_ref().expect("GitHub context");
        assert!(!context.contains(github));
        assert!(!context.contains("SyntheticBody"));
    }

    #[test]
    fn unicode_prefix_keeps_absolute_spans_on_character_boundaries() {
        let github = "ghp_FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let text = format!("προοίμιο\ntoken={github}\nτέλος");
        let findings = scan_text_unredacted(&text, "unicode");
        assert_eq!(findings[0].raw_secret(), github);
        let context = findings[0].safe().context.as_ref().expect("safe context");
        assert!(!context.contains(github));
        assert!(context.contains("προοίμιο"));
        assert!(context.contains("τέλος"));
    }

    #[test]
    fn context_is_omitted_when_neighbor_line_exceeds_scan_limit() {
        let github = "ghp_GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        let text = format!("{}\ntoken={github}", "x".repeat(MAX_SCANNED_LINE_BYTES + 1));
        let findings = scan_text(&text, "oversized-neighbor");
        let finding = findings
            .iter()
            .find(|f| f.detector == "github_pat")
            .expect("GitHub finding");
        assert!(finding.context.is_none());
    }

    #[test]
    fn span_normalization_merges_overlapping_and_adjacent_ranges() {
        let merged = merge_spans([8..12, 2..6, 5..9, 12..15, 20..21]);
        assert_eq!(merged, vec![2..15, 20..21]);
    }

    #[test]
    fn default_finding_serialization_and_debug_hold_no_raw_secret() {
        let secret = "ghp_HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH";
        let finding = scan_text(secret, "safe-model")
            .into_iter()
            .find(|finding| finding.detector == "github_pat")
            .expect("GitHub finding");
        let json = serde_json::to_string(&finding).unwrap();
        let debug = format!("{finding:?}");
        assert!(!json.contains(secret));
        assert!(!debug.contains(secret));
        assert!(!json.contains("raw_match"));
        assert!(json.contains("fingerprint"));
        assert!(json.contains("redacted"));
    }

    #[test]
    fn unsafe_finding_debug_still_hides_raw_secret() {
        let secret = "ghp_IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII";
        let finding = scan_text_unredacted(secret, "unsafe-debug")
            .into_iter()
            .find(|finding| finding.safe().detector == "github_pat")
            .expect("GitHub finding");
        assert_eq!(finding.raw_secret(), secret);
        assert!(!format!("{finding:?}").contains(secret));
    }
}
