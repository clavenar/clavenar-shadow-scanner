# Manual release tests

Use synthetic credentials only. Never scan live data while validating a
release candidate.

## Default-output non-disclosure

1. Create a temporary UTF-8 fixture containing two synthetic credentials on
   one line, another on a neighboring line, a bounded synthetic PEM private-key
   block, and a Unicode prefix.
2. Run the candidate binary three times against the fixture directory: default
   human output, `--json`, and `--sarif`.
3. Confirm each command exits `2`, reports the expected critical findings, and
   contains none of the complete synthetic credentials or PEM body lines.
4. Confirm contexts replace every detected span, including credentials that
   belong to a different finding.

## Fail-closed context

1. Put a synthetic credential within two lines of a line longer than 4 KiB.
2. Confirm the finding remains present but its context is omitted.
3. Repeat with an unterminated synthetic PEM block and confirm its context is
   omitted. If another finding has a window intersecting that block, confirm
   the PEM material is redacted there.

## Explicit unredacted output

1. Run human and JSON output with `--unredacted` against the synthetic fixture.
2. Confirm the warning banner is present in human output and JSON has `raw`,
   `"unsafe_output": true`, and a prominent warning. Treat both outputs as
   secret-bearing data and delete them immediately.
3. Confirm `github ... --unredacted` and `slack --unredacted` fail before source
   access, and `--sarif --unredacted` is rejected as a CLI conflict.

## Safe data model

1. Run the safe-model unit and integration suite and confirm direct `Finding`
   serialization plus safe/unsafe debug output contains no complete credential.
2. Confirm default JSON has no `raw` member and still carries `fingerprint` and
   `redacted` fields.

## Typed coverage outcome

1. Scan one clean UTF-8 file with human, JSON, and SARIF output. Confirm all
   formats report one object, its exact byte count, zero skips/errors,
   `truncated=false`, and `partial=false`.
2. Add one synthetic binary file and one file over 1 MiB. Confirm findings from
   the readable file remain, both excluded files are counted as skipped, and
   `partial=true` in human, JSON, and SARIF coverage.
3. Scan a nonexistent local root. Confirm JSON contains a structured `walk`
   source error, zero scanned objects, and `partial=true`, without file content
   or a credential value in the error.
4. Run the GitHub and Slack source-failure unit tests. Confirm repository and
   conversation-list failures return typed partial outcomes instead of an
   empty, complete result.
5. Repeat the complete synthetic-credential corpus and confirm adding coverage
   metadata does not place any raw value in default human, JSON, or SARIF.

## GitHub truncation and safe ignored-file mode

1. Run the deterministic GitHub mock tests. Confirm a recursive-tree response
   with `truncated=true` retains returned blob findings/counts while setting
   both `coverage.truncated` and `coverage.partial`; confirm one failed blob in
   a mixed tree leaves the successful count and adds a structured `blob` error.
2. Create a temporary Git repository whose `.gitignore` excludes a synthetic
   `.env` credential. Confirm the standard local scan does not report it and
   `local <path> --secrets-mode` does, with redacted output.
3. Put separate synthetic credentials in `.git/config`,
   `node_modules/.env`, and a file outside the root reached only by a symlink.
   Confirm secrets mode reports none of them and records no path outside the
   canonical root.
4. Confirm secrets mode deduplicates files seen by both walks and retains the
   size, binary, and invalid-UTF-8 skips from the standard scanner.

## Static release artifact

1. Download the tarball and `.sha256` companion for the target architecture.
2. Verify the checksum before extraction.
3. Run `--version`, repeat the default-output non-disclosure test, and delete
   the temporary fixture and output files.
