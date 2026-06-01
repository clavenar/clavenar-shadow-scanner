# clavenar-shadow-scanner

[![CI](https://github.com/clavenar/clavenar-shadow-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/clavenar/clavenar-shadow-scanner/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](./LICENSE)

Free discovery tool that scans GitHub orgs, Slack workspaces, and local
filesystems for unauthorized agent credentials — AI provider keys
(Anthropic, OpenAI, Google AI, xAI, Groq, Hugging Face, Voyage, Cohere,
Mistral), cloud / edge (AWS, GCP, Azure, Cloudflare, DigitalOcean,
Fly.io), CI / deploy platforms (Vercel, Netlify, Railway), dev
platforms (GitHub, GitLab, Atlassian, Sourcegraph, Slack bot tokens,
Slack webhooks, Stripe, NPM), database / data plane (PlanetScale,
Supabase service-role, Neon Postgres URLs), and messaging (Telegram,
Discord, SendGrid) — plus raw PEM private keys and JWTs.

The premise: organisations are deploying AI agents informally — random
scripts using API keys, bots running on someone's laptop, "just for the
demo" creds checked into a repo. The shadow scanner tells an
organisation what's already in places it shouldn't be, before someone
else finds it first.

Sequence diagrams for the five primary paths — CLI dispatch + the
shared `emit` pipeline, the gitignore-aware local scan, the GitHub
owner/repo scan with rate-limit backoff, the Slack workspace
cursor-paginated scan, and the per-line detector engine + Report
aggregation — plus a request decision-tree flowchart, live in
[`docs/SEQUENCES.md`](docs/SEQUENCES.md).

## Quick start

```bash
# Scan your laptop's home directory.
clavenar-shadow-scanner local ~

# Scan one repo on GitHub. (Set GITHUB_TOKEN — public API caps at 60 req/hr.)
GITHUB_TOKEN=ghp_… clavenar-shadow-scanner github clavenar/clavenar-proxy

# Scan every repo under an org.
GITHUB_TOKEN=ghp_… clavenar-shadow-scanner github vanteguardlabs

# Scan Slack history (last 14 days, every channel the bot is in).
SLACK_BOT_TOKEN=xoxb-… clavenar-shadow-scanner slack
```

Output is **redacted by default** — secrets render as `<first4>…<last4>`.
Pass `--unredacted` if you actually need the raw key in the report
(e.g. for triage). The human-readable report leads with a banner
warning the file is now a secrets file. JSON output via `--json`,
SARIF v2.1.0 via `--sarif` (consumed by GitHub Code Scanning, Sonatype,
Snyk, and most modern code-review tools — always redacted regardless
of `--unredacted`).

## Subcommands

```
local <path>                      Scan a directory (gitignore-aware).
github <owner>[/<repo>] [...]     Scan one repo or every repo under an owner.
  --include-forks                 Also scan forked repos.
  --include-archived              Also scan archived repos.
slack [--days N]                  Scan recent Slack history (default 14d).
```

Common output flags (every subcommand):

```
--json                            Machine-readable JSON. Mutually exclusive with --sarif.
--sarif                           SARIF v2.1.0 (always redacted; ready for GitHub
                                  Code Scanning's `upload-sarif` action and friends).
--unredacted                      Show secrets in plaintext in JSON / human output
                                  (default: redact). Ignored under --sarif.
--severity-min critical|high|medium|low
                                  Drop findings below this severity (default: low).
```

### CI integration

```yaml
# .github/workflows/secrets-scan.yml
- run: clavenar-shadow-scanner local . --sarif > results.sarif
  continue-on-error: true       # exit 2 on findings — surface in the SARIF UI instead.
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

SARIF severity maps to GitHub Code Scanning's three-level annotation
system: `Critical`/`High` → `error` (red), `Medium` → `warning`
(yellow), `Low` → `note` (blue). Each result carries a stable
`fingerprints["clavenar/v1"]` (SHA-256 of the secret) so re-runs
auto-resolve once the secret is removed.

## Auth

| Source | Env var          | Notes                                                                |
|--------|------------------|----------------------------------------------------------------------|
| local  | (none)           | Reads files directly; no creds needed.                               |
| github | `GITHUB_TOKEN`   | PAT or App token. Optional but strongly recommended (rate limits).   |
| slack  | `SLACK_BOT_TOKEN`| `xoxb-…`. Required scopes: `channels:read`, `channels:history` (and `groups:*` for private channels). |

## Exit codes

- `0` — no findings (or only `medium`/`low` findings).
- `2` — at least one `high` or `critical` finding. CI-friendly.
- `1` — runtime error (bad auth, network, etc.).

## Output safety

The scanner finds secrets, so the report itself can become a secrets
file:

- **Default**: secrets render as `<first4>…<last4>`. The JSON has no
  `raw` field. The human report has no banner.
- **`--unredacted`**: secrets render in full. JSON includes `raw`.
  Human report leads with `!! UNREDACTED OUTPUT — this report contains
  live secrets. Treat it as such.`
- Findings dedupe by SHA-256 fingerprint of the raw secret, so the
  same key in 12 files becomes one entry with 12 locations.

## Detection rules

Hand-written regex set with optional Shannon-entropy + length gates.
~37 detectors covering:

| Category            | Detectors                                                              |
|---------------------|------------------------------------------------------------------------|
| AI provider keys    | Anthropic (`sk-ant-…`), OpenAI (`sk-…`), Google AI (`AIza…`), xAI / Grok (`xai-…`), Groq (`gsk_…`), Hugging Face (`hf_…`), Voyage (`pa-…`), Cohere, Mistral |
| Cloud / edge        | AWS access key + secret, GCP service-account JSON, Azure client secret, Cloudflare API token, DigitalOcean (`dop_v1_…`), Fly.io (`FlyV1 fm…`) |
| CI / deploy         | Vercel, Netlify (`nfp_…`), Railway                                     |
| Dev-platform tokens | GitHub token (PAT / OAuth / App / refresh — `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`), GitLab (`glpat-…`), Atlassian (`ATATT3…`), Sourcegraph (`sgp_…`), Slack bot/user/app tokens, Slack webhook URLs, Stripe live/test, NPM, JWT |
| Database / data     | PlanetScale (`pscale_pw_…`), Supabase service-role JWT, Neon Postgres URL (`*.neon.tech` with embedded password) |
| Messaging           | Telegram bot tokens, Discord bot tokens, SendGrid (`SG.<22>.<43>`)     |
| Cryptographic       | PEM private-key block opener                                           |
| Generic backstop    | High-entropy string near `key`/`token`/`secret`/`password` keyword     |

The generic backstop only fires when (a) entropy ≥ 4.0 bits/byte
(rules out short identifiers), (b) length ≥ 24 chars, and (c) the line
contains a sensitive keyword. Tuned to keep false-positive rate low
enough for clean CI integration.

## What it doesn't do (yet)

- **Slack threads + archived channels**: out of scope for the MVP.
  The high-value find is "did anyone paste a key into a non-archived
  channel I'm a member of."
- **GitHub Enterprise**: only `api.github.com` is wired; Enterprise
  endpoint support is a base-URL knob.
- **Incremental scanning**: every invocation is a full scan. A delta
  cache (skip blobs whose SHA we've already scanned) is a follow-up.
- **Verifiers**: no live API call to confirm the secret is active.
  Plumbing this in would need separate auth and is rate-limit-heavy.

## License / shipping

This is the free discovery tool — the top-of-funnel surface for the
broader Clavenar product. Open-source under
[Apache-2.0](./LICENSE), distributed as a single binary, no telemetry.
The point is to find the problem; the remediation pipeline
(`clavenar-proxy`, `clavenar-policy-engine`, `clavenar-ledger`,
`clavenar-hil`) is what converts.

## Next step: stop the credentials from leaking

Once the scanner shows you what's already exposed, route your AI
agents through [clavenar-lite](https://github.com/clavenar/clavenar-lite)
to prevent exfiltration: a single-binary MCP proxy with
human-in-the-loop approval and an append-only audit chain. Same
distribution model (one static binary), same Apache-2.0 license,
no telemetry.
