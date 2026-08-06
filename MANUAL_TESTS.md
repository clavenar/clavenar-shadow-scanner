# Manual release tests

These tests cover release-artifact, operating-system, remote-source, and
output-handling boundaries that the automated suite cannot prove by itself.
Use synthetic credentials only. Never scan live organization, repository,
workspace, or home-directory data while validating a release candidate.

## Run contract

Record the candidate version, source tag/SHA, architecture, operating system,
opaque tester ID, and UTC start. Run the automated baseline first:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release
```

Create a private disposable root and point `SCANNER` at the exact candidate
binary. Keep unsafe output inside this root and never attach it to evidence:

```sh
umask 077
SCANNER_RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/clavenar-shadow-manual.XXXXXX")
cleanup() { rm -rf -- "$SCANNER_RUN_DIR"; }
trap cleanup EXIT HUP INT TERM
export SCANNER_RUN_DIR
SCANNER=${SCANNER:-${CARGO_TARGET_DIR:-target}/release/clavenar-shadow-scanner}
export SCANNER
```

For each scenario record `PASS`, `FAIL`, `BLOCKED`, or `SKIPPED`, UTC finish,
sanitized evidence URI/digest, and issue. Evidence may contain detector names,
counts, exit codes, fingerprints, and redacted values, but never fixture bytes,
raw context, access tokens, or unsafe reports. Confirm cleanup before declaring
the run complete.

## SS-OUT-01 — default output is context-free and non-disclosing

**Goal.** Prove every default output model is unable to recover matched or
neighboring synthetic credentials.

**Steps.**
1. Create a UTF-8 fixture containing distinct synthetic credentials on the same
   line and neighboring lines, a complete bounded synthetic PEM block, a
   Unicode prefix, and harmless surrounding text.
2. Run the candidate against its directory in default human, `--json`, and
   `--sarif` modes, capturing stdout/stderr separately under
   `$SCANNER_RUN_DIR` and recording each exit code.
3. Require exit `2`, expected critical/high detector names, redacted display
   values, and 64-lowercase-hex fingerprints in every applicable format.
4. Search all default output bytes for every complete fixture value and PEM
   body line. Confirm no finding has a `raw` field and no default finding has
   context. SARIF remains redacted and carries coverage only under
   `runs[0].properties`.

**Expected.** Findings are useful by detector, severity, redacted value,
fingerprint, and location, but default human/JSON/SARIF cannot recover a secret
or neighboring text. Default CLI scans and both remote sources are context-free
by construction.

**Failure signal.** A raw value, PEM body, neighboring context, unsafe marker,
or recoverable field appears; formats disagree on the finding set; or a
high/critical fixture returns an exit other than `2` when coverage is complete.

## SS-CTX-01 — explicit library context remains fail-closed

**Goal.** Prove best-effort context exists only through the explicit library
API and is omitted whenever safe rendering cannot be established.

**Steps.** Run these focused owner tests and inspect failures without copying
their synthetic values into the run receipt:

```sh
cargo test --locked detector::tests::context_
cargo test --locked detector::tests::overlapping_detector_spans_merge_before_context_rendering
cargo test --locked detector::tests::complete_pem_block_is_one_span_and_fully_redacted_from_context
cargo test --locked detector::tests::unterminated_pem_omits_its_context_and_redacts_neighbor_contexts
cargo test --locked detector::tests::unicode_prefix_keeps_absolute_spans_on_character_boundaries
```

**Expected.** `scan_text_with_context` redacts every known overlapping,
same-line, and neighboring span before rendering a ±2-line window. A line over
4 KiB or an unterminated PEM intersecting the window omits context. Ordinary
`scan_text`, local/GitHub/Slack scanning, and all CLI formats still omit it.

**Failure signal.** Context is enabled implicitly, one detected span survives
inside another finding's window, Unicode breaks offsets, an unsafe window is
rendered, or remote/default output acquires context.

## SS-UNSAFE-01 — explicit unredacted output is local-only

**Goal.** Prove raw output requires an unmistakable, local-only opt-in and
cannot be combined with remote access or SARIF.

**Steps.**
1. Run local human and JSON output with `--unredacted` against the disposable
   fixture. Keep both files under `$SCANNER_RUN_DIR` and delete them before
   recording evidence.
2. Confirm human output begins with the unsafe warning. Confirm JSON has the
   separate unsafe model's `raw`, `"unsafe_output": true`, and warning, while
   debug formatting still hides the raw value.
3. With `GITHUB_TOKEN` and `SLACK_BOT_TOKEN` unset, run `github ...
   --unredacted` and `slack --unredacted`; both must reject the mode before any
   credential or network access. Require `--sarif --unredacted` to fail as a
   CLI conflict.

**Expected.** Only an explicit local human/JSON invocation emits raw values and
it is visibly marked. Remote and SARIF paths cannot construct that output.

**Failure signal.** Raw output lacks a warning, appears in debug/default/SARIF,
or a remote command performs source access before rejecting `--unredacted`.

## SS-MODEL-01 — safe identities and portable locations

**Goal.** Prove deduplication identity and locations remain stable without
embedding raw material or host-specific paths.

**Steps.**
1. Place the same synthetic credential in two root-relative paths, including a
   path with Unicode, spaces, `#`, and `%`; scan twice from different absolute
   parent directories.
2. Confirm one finding has both locations and the same full 64-hex SHA-256
   fingerprint across runs. Default serialization/debug contains no raw field.
3. Confirm local locations are relative to the selected root. In SARIF, require
   URI-reference percent encoding and no absolute host prefix.
4. Run the deterministic location and URL-component checks:
   ```sh
   cargo test --locked output::sarif::tests::sarif_maps_github_locations_to_encoded_repository_paths
   cargo test --locked sources::github::tests::blob_url_percent_encodes_every_untrusted_component
   cargo test --locked sources::slack::tests::pagination_cursor_is_percent_encoded_by_url_builder
   ```

**Expected.** The same secret deduplicates across locations/runs, different
synthetic secrets do not collide, and locations are portable and encoded.

**Failure signal.** Fingerprints are truncated/unstable, raw data participates
in a display/debug path, an absolute host path leaks, or untrusted path/ref
components alter a request URL or SARIF structure.

## SS-COV-01 — exclusions and incomplete coverage remain distinct

**Goal.** Prove intentional out-of-scope objects are visible without being
misreported as incomplete scans, while in-scope failures always set partial.

**Steps.**
1. Scan one clean UTF-8 file with human, JSON, and SARIF output. Require one
   object, exact byte count, zero skips/exclusions/errors,
   `truncated=false`, and `partial=false`.
2. Add one binary file and one file over 1 MiB. Require
   `objects_excluded=2`, `exclusion_reasons.binary_file=1`,
   `exclusion_reasons.oversized_file=1`, zero skips, and `partial=false`.
3. As a non-root user on Unix, add one in-scope mode-000 text file. Require one
   skip, `partial=true`, and no file content in the structured error. Restore
   its mode during cleanup.
4. Scan a nonexistent root. Require a structured `walk` error, zero scanned
   objects, `partial=true`, and no raw path-adjacent content.
5. Run the exact source-failure checks. Successful objects/findings must
   survive beside structured per-object errors; total source failure must not
   become an empty complete result:
   ```sh
   cargo test --locked sources::local::tests::missing_root_is_a_typed_partial_error
   cargo test --locked sources::github::tests::mixed_blob_failure_retains_success_and_structured_error
   cargo test --locked sources::github::tests::repository_failure_is_a_typed_partial_error
   cargo test --locked sources::slack::tests::conversation_failure_is_a_typed_partial_error
   cargo test --locked sources::slack::tests::mixed_channel_failure_exceeds_default_partial_threshold
   ```

**Expected.** Binary, oversized, archived, fork (when excluded), and empty
message scope decisions increment exclusions only. An in-scope unreadable
object, source error, or truncation sets `partial=true` in every format.

**Failure signal.** An exclusion contributes to incomplete percentage, an
in-scope failure remains complete, coverage counts disagree with reason maps,
or one source reports different semantics than another.

## SS-COV-02 — coverage decision and exit precedence

**Goal.** Prove all output formats make the same source-neutral decision and a
coverage failure takes precedence over findings.

**Steps.**
1. Scan an empty directory: require exit `0`, status `complete`, zero attempted
   objects, and recommended exit `0`.
2. As a non-root Unix user, scan nine clean text files and one mode-000 in-scope
   file. At the default 10% maximum require exit `0`,
   `partial_within_threshold`, and exactly 10%; at `9.9` require exit `3` and
   `threshold_exceeded`.
3. Require a nonexistent root to return exit `3` / `total_failure`, even with a
   100% threshold. Run `cargo test --locked
   sources::github::tests::truncated_tree_sets_typed_partial_coverage_and_keeps_results`
   and require `truncated`, `partial=true`, retained returned blobs, and exit
   recommendation `3` at every threshold.
4. Put one high-severity synthetic finding beside the unreadable file. Require
   exit `3` to take precedence over finding exit `2` while output stays
   redacted.
5. Compare human, JSON, SARIF, and explicit unsafe-local reports for the same
   counts, percentage, configured maximum, status, and recommended exit.

**Expected.** Incomplete percentage is `(skips + source errors) / (scanned +
skips + source errors) * 100`; exclusions never enter it. Exactly the threshold
passes, strictly above fails, and truncation/total failure always fail.

**Failure signal.** Boundary comparison is non-strict, a threshold masks
truncation/total failure, finding exit `2` hides coverage exit `3`, or formats
disagree.

## SS-BOUND-01 — long-line and finding ceilings are visible

**Goal.** Prove work limits prevent regex/report exhaustion without silently
dropping secrets or presenting a truncated result as complete.

**Steps.**
1. Put one synthetic credential beyond byte 4096 on a long Unicode-safe line
   and another across an overlapping-window boundary. Scan with the candidate.
2. Require each credential exactly once, with no context and valid character
   offsets; the line itself must not count as skipped or excluded.
3. Run `cargo test --locked
   detector::tests::long_lines_are_scanned_in_overlapping_windows_without_duplicates`
   and `cargo test --locked
   detector::tests::per_text_finding_limit_is_explicitly_reported`.
4. Exercise the per-object and aggregate ceilings with the deterministic owner
   fixtures. Require retained findings plus `truncated=true`, `partial=true`,
   and exit `3` rather than silent dropping.

**Expected.** Overlapping UTF-8-safe windows find long-line secrets once. Every
finding ceiling is observable through truncation and the fail-closed exit.

**Failure signal.** A long line is skipped, a boundary match disappears or
duplicates, offsets split UTF-8, or any ceiling returns complete/exit `0` or
`2`.

## SS-REMOTE-01 — remote scope, pagination, and transport boundaries

**Goal.** Prove remote scans cover the declared scope exactly and untrusted
owner/repository/path/ref/cursor values cannot redirect or confuse requests.

**Pre-conditions.** Synthetic GitHub owner/repository and Slack workspace with
least-privilege, short-lived tokens read from the environment; no live customer
data. Skip the live portion if such fixtures do not exist and retain the owner
tests as evidence.

**Steps.**
1. Run `cargo test --locked sources::github::tests` and `cargo test --locked
   sources::slack::tests`. Require HTTPS except explicit IP-loopback test
   servers, reject URL credentials, percent-encode every untrusted
   component/cursor, and bound response bodies, pagination, lookback, object
   count, and finding count.
2. In the synthetic GitHub source, scan a repository, then its owner. Compare
   declared scope and counts with forks/archives excluded and explicitly
   included. A recursive-tree `truncated=true` must retain returned findings
   but force exit `3`.
3. In synthetic Slack, verify cursor pagination, day bound, membership/channel
   scope, archived and empty-message exclusions, and a mixed history failure.
4. Confirm neither source emits context or accepts `--unredacted`; errors and
   request labels contain no token, response body, or raw message/blob.

**Expected.** Coverage declares exactly what was considered, excluded, scanned,
or incomplete. Transport and pagination cannot escape the configured API
origin or limits, and partial remote data is never reported complete.

**Failure signal.** Owner fallback occurs on errors other than the reviewed
not-found case, pagination loses/duplicates scope, archive/fork/message policy
is invisible, truncation passes, an untrusted component alters origin/query
structure, or tokens/content leak.

## SS-SECRETS-01 — ignored-file mode is root-confined

**Goal.** Prove `--secrets-mode` broadens only the reviewed credential-oriented
scope and cannot follow links or traverse dependency/VCS trees.

**Steps.**
1. Create a temporary Git repository whose `.gitignore` excludes a synthetic
   `.env` credential. Standard local scan must not find it; `--secrets-mode`
   must find it with redacted output.
2. Put distinct synthetic credentials in `.git/config`, `node_modules/.env`, a
   build/cache directory, and a file outside the root reachable only through a
   symlink. Require no finding and no recorded path for any of them.
3. Put the same eligible file in both standard and supplemental walks. Require
   one scanned object/location. Add binary, invalid-UTF-8, and oversized
   eligible files; require visible exclusions, not skips or partial coverage.
4. On Linux, run these owner checks:
   ```sh
   cargo test --locked sources::local::tests::confined_open_rejects_symlinks_and_paths_outside_root
   cargo test --locked sources::local::tests::secrets_mode_adds_ignored_credentials_without_following_unsafe_paths
   cargo test --locked sources::local::tests::skips_oversized_file
   ```
   While repeatedly scanning another disposable tree, replace one eligible
   path with an outside-root symlink and grow another regular file past 1 MiB.
   The scanner may finish the already opened regular inode or reject/exclude
   it, but it must never read the link target or more than the bounded cap.
   Require root-relative `openat2` confinement (`BENEATH`, no symlink or
   magic-link resolution).

**Expected.** Secrets mode finds ignored credential files only inside the
canonical root, deduplicates both walks, and retains the normal scope/coverage
model.

**Failure signal.** VCS/dependency/build/cache/outside-root content is read, a
symlink or race escapes confinement, a file is counted twice, or intentional
binary/size/encoding exclusions become partial.

## SS-REL-01 — static release identity and provenance

**Goal.** Prove the downloaded artifact matches the reviewed tag, checksum,
static-link contract, SBOM, and GitHub artifact attestations before executing
it.

**Steps.**
1. In `$SCANNER_RUN_DIR`, download the target architecture tarball, its
   `.sha256`, and `clavenar-shadow-scanner.cdx.json` from the exact `v<VERSION>`
   release. Set `ASSET` to the downloaded tarball name. Confirm the tag equals
   `Cargo.toml` and the release workflow's source SHA. Use a GitHub CLI version
   that exposes `gh attestation verify`.
2. Verify both ordinary provenance and the distinct CycloneDX predicate:
   ```sh
   sha256sum --check "$ASSET.sha256"
   for file in "$ASSET" "$ASSET.sha256" clavenar-shadow-scanner.cdx.json; do
     gh attestation verify "$file" \
       --repo clavenar/clavenar-shadow-scanner \
       --source-ref "refs/tags/v$VERSION" \
       --signer-workflow clavenar/clavenar-shadow-scanner/.github/workflows/release.yml
   done
   gh attestation verify "$ASSET" \
     --repo clavenar/clavenar-shadow-scanner \
     --source-ref "refs/tags/v$VERSION" \
     --signer-workflow clavenar/clavenar-shadow-scanner/.github/workflows/release.yml \
     --predicate-type https://cyclonedx.org/bom
   ```
3. List the archive before extraction; require exactly one regular
   `clavenar-shadow-scanner` binary and no absolute/parent path. Extract only
   after checks. On the matching Linux architecture, require `file` to report a
   static executable, no `readelf -l` program interpreter, and no `readelf -d`
   `NEEDED` entry.
4. Run `--version`, SS-OUT-01, SS-COV-01, and SS-BOUND-01 with the downloaded
   binary. Confirm the CycloneDX document names the same package/version and
   parses without external resolution.

**Expected.** Every subject is digest/attestation-bound to the reviewed release,
the binary is fully static and version-correct, the SBOM matches, and runtime
behavior matches the source candidate.

**Failure signal.** Checksum/attestation/SBOM/tag mismatch, unsafe archive path,
dynamic interpreter/dependency, version mismatch, missing architecture asset,
or any behavioral difference from the source-built candidate.
