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
2. Confirm the warning banner is present in human output and JSON has a `raw`
   field. Treat both outputs as secret-bearing data and delete them immediately.
3. Run `--sarif --unredacted` and confirm SARIF remains redacted.

## Static release artifact

1. Download the tarball and `.sha256` companion for the target architecture.
2. Verify the checksum before extraction.
3. Run `--version`, repeat the default-output non-disclosure test, and delete
   the temporary fixture and output files.
