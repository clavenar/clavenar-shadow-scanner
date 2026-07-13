<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-shadow-scanner — free discovery tool: scans GitHub/Slack/local-fs for leaked AI-provider, cloud, and dev-platform credentials

## Build, test, lint

```bash
cargo build                                      # release: cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo deny check all                             # supply-chain
cargo cyclonedx --format json --describe crate   # SBOM
cargo build --release --locked --target x86_64-unknown-linux-musl   # release artifact (also aarch64-unknown-linux-musl)
```

Release binaries are fully static musl, both arches, pinned lockfile — the
release workflow asserts the x86_64 binary has no dynamic deps via `ldd`.
Host-build caveat: `CARGO_TARGET_DIR=/tmp/clavenar-shadow-scanner-target` (a repo `target/` may be root-owned from prior docker builds).

Run: CLI binary `clavenar-shadow-scanner` — no listener, no daemon; it scans and exits. Subcommands:
`local <path>` · `github <owner>[/<repo>]` (scans the default branch of non-fork, non-archived repos;
`--include-forks` / `--include-archived` widen) · `slack [--days N]`. Common flags on every subcommand:
`--json` | `--sarif` (mutually exclusive) · `--unredacted` · `--severity-min critical|high|medium|low`.
Auth via env: `GITHUB_TOKEN` (optional; public API caps at 60 req/hr), `SLACK_BOT_TOKEN` (`xoxb-…`). `local` needs no creds.
Exit codes: `0` no findings (or only medium/low) · `2` ≥1 high/critical (CI-friendly) · `1` runtime error.

## Layout
- `src/main.rs` — CLI entry. clap `Cli`/`Command` enum (`Local`/`Github`/`Slack`); `OutputArgs` flattened into each subcommand so all share one output surface.
- `src/lib.rs` — public API: re-exports `scan_text`, `detectors`, `redact`, `shannon_entropy`, `Detector`, `Finding`, `Severity`. Library consumers (tests, future SDK) call these directly; `main.rs` is a thin wrapper.
- `src/detector.rs` — ~37 hand-written regex detectors + optional Shannon-entropy/length gates; the per-line scan engine and `Severity`.
- `src/sources/` — per-platform fetchers, each yielding `(location, text)` pairs: `local.rs` (gitignore-aware walk via the `ignore` crate), `github.rs` (owner/repo scan, rate-limit backoff), `slack.rs` (cursor-paginated workspace history; `DEFAULT_LOOKBACK_DAYS`).
- `src/output/` — `mod.rs` (`Report`, redaction, `filter_by_min_severity`), `sarif.rs` (SARIF v2.1.0 emitter).
- `tests/` — integration tests. `docs/SEQUENCES.md` — sequence diagrams for the five primary paths + the request decision-tree. `docs/DETECTORS.md` — detector catalog (37 rules, gates, SARIF contract); keep in sync with `build_detectors`.

## Conventions & invariants

- After adding or updating a feature, also update the relevant `MANUAL_TESTS*` file(s) when needed.

- **Redacted by default.** Secrets render `<first4>…<last4>`; JSON has no `raw` field. `--unredacted` shows plaintext, adds `raw`, and the human report leads with a `!! UNREDACTED OUTPUT` banner. SARIF is **always redacted** regardless of `--unredacted`.
- **Findings dedupe by SHA-256 fingerprint** of the raw secret — the same key in 12 files collapses to one finding with 12 locations. SARIF emits this as a stable `fingerprints["clavenar/v1"]` so re-runs auto-resolve once the secret is removed.
- **SARIF severity → GitHub Code Scanning:** Critical/High → `error`, Medium → `warning`, Low → `note`.
- **Generic backstop detector** only fires on entropy ≥ 4.0 bits/byte AND length ≥ 24 AND a `key`/`token`/`secret`/`password` keyword on the line — keep that gate; it is what holds the false-positive rate low enough for clean CI.
- **rustls-tls, no OpenSSL.** `reqwest` is `default-features = false` + `rustls-tls` on purpose — this is the zero-friction top-of-funnel tool; don't drag OpenSSL onto end-user laptops.
- **No telemetry, ever.** Single static binary, Apache-2.0, no phone-home. Don't add network calls beyond the scanned-source APIs.
- **Binary-only release:** no container image, no published crate (`publish = false`). Distribution is `curl | tar | run` of the musl binary, or `cargo install --git`. Release tag `v*` must equal `Cargo.toml` `version` (workflow asserts).
- `edition = "2024"`. `[lints.rust] unreachable_pub = "warn"` — keep non-API items non-`pub`.
- Rust house rules: clippy `-D warnings` is the floor — fix the code, don't `#[allow]` (note the reason if a documented false positive). Anything in a `pub` fn signature must itself be `pub` (`private_interfaces`). Tests go at file bottom in `#[cfg(test)] mod tests` (`items_after_test_module`). Prefer `writeln!` over `write!(…, "\n")` and let-chains over nested `if let`. Doc comments: prose only — no `+ ` line-start continuations (`doc_lazy_continuation`).
- Commit subjects must start with a lowercase letter.
- `deny.toml` is synced verbatim from `clavenar-specs` — edit it there first, then mirror the exact bytes.

## Pointers
README.md · SECURITY.md · docs/SEQUENCES.md · docs/DETECTORS.md
