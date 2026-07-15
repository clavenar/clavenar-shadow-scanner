# clavenar-shadow-scanner — detector catalog

The scanner ships 37 hand-written detectors, built once by
`build_detectors` in [`src/detector.rs`](../src/detector.rs) and cached
for the process by `detectors`. Each is a `Detector { name, description,
severity, pattern, min_entropy, min_length }`: a regex over a single
line, plus optional Shannon-entropy (bits/byte) and length floors the
matched secret must clear. When the regex has a capture group, group 1
is the secret; otherwise the whole match is. `scan_text` runs every
detector against every line under 4 KiB and yields a `Finding` per hit.

Detection and context rendering are separate passes. `scan_text` first
records the exact absolute byte span of every accepted match, expands a
bounded PEM private key through its matching footer, sorts the spans, and
merges overlapping or adjacent ranges. Only then does it render each
±2-line context window, redacting every merged span that intersects the
window. Context is omitted if the window includes an unscanned line over
4 KiB or if a multi-line PEM block is unterminated. Explicit local
`--unredacted` output still exposes the aggregate raw match by request;
human, JSON, and SARIF defaults use only redacted aggregates and contexts.

Severity is load-bearing. The CLI's `emit` (in
[`src/main.rs`](../src/main.rs)) exits `2` when any surviving aggregate
is `Critical` or `High`, and `0` otherwise — so `Medium`/`Low` findings
are informational and never fail CI. A runtime error exits `1`.
`Severity` orders `Critical < High < Medium < Low`, which is why
`--severity-min` filtering and the "higher tier wins" aggregate merge in
[`src/output/mod.rs`](../src/output/mod.rs) treat the smaller ordinal as
more severe.

## Detectors

Grouped by the section banners in `build_detectors`. "Shape / anchor"
summarizes the regex; "Entropy" / "Min len" are the `min_entropy` and
`min_length` gates (`—` when unset). Anchored detectors require the
vendor keyword on the same line to keep precision high.

### AI provider keys

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `anthropic_api_key` | Critical | `sk-ant-(api\|admin)<NN>-` + ≥32 `[A-Za-z0-9_-]` | — | — |
| `openai_api_key` | Critical | `sk-` / `sk-proj-` / `sk-svcacct-` / `sk-admin-` + ≥32 | 3.5 | 20 |
| `voyage_api_key` | High | `pa-` + ≥40 `[A-Za-z0-9_-]` | 3.5 | — |
| `cohere_api_key` | High | 40-char alnum anchored near `cohere` | 3.5 | 40 |
| `mistral_api_key` | High | 32–40 alnum anchored near `mistral` | 3.5 | 32 |
| `google_ai_api_key` | Critical | `AIza` + 35 `[A-Za-z0-9_-]` | — | — |
| `xai_api_key` | Critical | `xai-` + 80 alnum | — | — |
| `groq_api_key` | Critical | `gsk_` + 52 alnum | — | — |
| `huggingface_token` | Critical | `hf_` + ≥30 alnum | — | — |

### Cloud provider keys

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `aws_access_key_id` | Critical | `AKIA`/`ASIA`/`AGPA`/`AIDA`/`AROA`/`AIPA`/`ANPA`/`ANVA`/`ABIA` + 16 `[A-Z0-9]` | — | — |
| `aws_secret_access_key` | Critical | 40-char base64ish anchored near `aws…secret…access…key` | 4.0 | 40 |
| `gcp_service_account_key` | Critical | `"private_key_id": "<40 hex>"` JSON marker | — | — |
| `azure_client_secret` | High | ≥34 `[A-Za-z0-9~._-]` anchored near `azure_client_secret` | 4.0 | 34 |
| `cloudflare_api_token` | High | 40-char base64ish anchored near `cloudflare` / `cf_api_token` | 4.0 | 40 |
| `digitalocean_pat` | Critical | `dop_v1_` + 64 hex | — | — |
| `fly_io_token` | High | `FlyV1 fm[12]_` + ≥40 base64 | — | — |

### Developer-platform tokens

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `github_pat` | Critical | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36–255 alnum | — | — |
| `slack_bot_token` | Critical | `xox[abprs]-` + ≥10 `[A-Za-z0-9-]` | — | — |
| `slack_webhook_url` | High | `https://hooks.slack.com/services/T…/B…/…` | — | — |
| `stripe_live_key` | Critical | `sk_live_` / `rk_live_` + ≥20 alnum | — | — |
| `stripe_test_key` | Low | `sk_test_` / `rk_test_` + ≥20 alnum | — | — |
| `private_key_pem` | Critical | Complete `-----BEGIN [RSA/EC/DSA/OPENSSH/PGP ]PRIVATE KEY-----` block through its matching footer | — | — |
| `jwt_token` | Medium | `eyJ….eyJ….<sig>` base64url triple | — | — |
| `npm_token` | High | `npm_` + 36 alnum | — | — |
| `gitlab_pat` | High | `glpat-` + ≥20 `[A-Za-z0-9_-]` | — | — |
| `atlassian_api_token` | High | `ATATT3` + ≥50 `[A-Za-z0-9_-]` | — | — |
| `sourcegraph_pat` | Medium | `sgp_` + ≥40 alnum | — | — |

### CI / deploy platforms

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `vercel_token` | High | 24-char alnum anchored near `vercel` | 4.0 | 24 |
| `netlify_pat` | High | `nfp_` + ≥40 alnum | — | — |
| `railway_token` | High | UUID anchored near `railway` | — | — |

### Database / data plane

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `planetscale_password` | Critical | `pscale_pw_` + ≥40 `[A-Za-z0-9_-]` | — | — |
| `supabase_service_role_jwt` | Critical | JWT-shaped value anchored near `supabase` | — | — |
| `neon_postgres_url` | Critical | `postgres(ql)://user:pass@*.neon.tech…` | — | — |

### Communications / messaging

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `telegram_bot_token` | Medium | `<8–10 digit id>:<35-char body>` | — | — |
| `discord_bot_token` | Medium | `[MN]<23–28>.<6–7>.<27–38>` base64-dotted | — | — |
| `sendgrid_api_key` | High | `SG.<22>.<43>` | — | — |

### Generic high-entropy backstop

| Detector | Severity | Shape / anchor | Entropy | Min len |
|---|---|---|---|---|
| `generic_high_entropy_secret` | Medium | ≥24 base64ish after `api_key`/`access_token`/`secret`/`auth_token`/`password`/`passwd`/`bearer` + `:`/`=` | 4.0 | 24 |

The entropy floor is documented in the module header of
[`src/detector.rs`](../src/detector.rs): random base64 lands 4.5–5.5
bits/byte and English prose ~4.0, so the 4.0 floor plus a length floor
keeps short deterministic identifiers from tripping the catch-all rule.

## SARIF output contract

`write_sarif` in [`src/output/sarif.rs`](../src/output/sarif.rs) emits a
SARIF v2.1.0 document — the schema GitHub Code Scanning, Sonatype, and
Snyk consume. It is **always redacted**, regardless of `--unredacted`,
because SARIF artefacts land in CI logs and PR annotations; `emit` in
[`src/main.rs`](../src/main.rs) enforces this by building the `Report`
with `unredacted && !sarif`.

- **Envelope.** `$schema` points at `sarif-2.1.0.json`, `version` is
  `"2.1.0"`, and there is a single `runs[0]` whose `tool.driver.name` is
  `clavenar-shadow-scanner` with `version` from `CARGO_PKG_VERSION` and
  an `informationUri`.
- **Rules.** One rule per detector, deduped in a `BTreeMap` keyed by
  detector name so ordering is deterministic across runs. First-seen
  wins; because aggregates are pre-sorted by `(severity, detector,
  fingerprint)` the first instance for a detector is its highest
  severity, which sets `defaultConfiguration.level`.
- **One result per (aggregate, location).** Same-fingerprint hits are
  **not** collapsed into one result with N locations — GitHub Code
  Scanning expects one annotation per `file:line`, and `result.locations`
  is reserved for related call-sites of the *same* finding, not the same
  secret in a different file.
- **Fingerprints.** Each result carries
  `fingerprints["clavenar/v1"]` — the SHA-256 of the raw secret
  truncated to 16 hex chars (`Finding::fingerprint`) — so re-runs
  auto-resolve a finding once the secret is removed.
- **Severity mapping.** `severity_to_sarif_level` collapses the
  four-tier severity onto SARIF's three levels: `Critical`/`High` →
  `error`, `Medium` → `warning`, `Low` → `note`.
- **Properties bag.** `runs[0].properties` carries `source`,
  `scanned_at` (RFC 3339), and `total_findings`; SARIF parsers ignore
  unknown keys.

---
*Re-verify against `build_detectors` / `Severity` in
[`src/detector.rs`](../src/detector.rs), `emit` in
[`src/main.rs`](../src/main.rs), `Report::from_findings` in
[`src/output/mod.rs`](../src/output/mod.rs), and `write` /
`severity_to_sarif_level` in [`src/output/sarif.rs`](../src/output/sarif.rs).*
