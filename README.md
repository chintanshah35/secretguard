# secretguard

Scan your source code for secrets, credentials, and PII before they reach production.

```bash
npx secretguard .
```

Exits with code `1` if any CRITICAL findings are detected (change it with `--fail-on`) — drop it into your CI pipeline and it just works.

## What it detects

95 built-in detection patterns covering cloud credentials, AI API keys, SaaS tokens, database credentials, private keys, and sensitive PII, grouped by severity.

**Credentials — CRITICAL**
- AWS access keys (`AKIA...`, `ASIA...`) and secret keys
- OpenAI API keys (`sk-...`, `sk-proj-...`, `sk-svcacct-...`)
- Anthropic API keys (`sk-ant-...`)
- Groq (`gsk_...`) and Replicate (`r8_...`) API tokens
- GitHub tokens (`ghp_`, `ghs_`, `gho_`, `github_pat_`)
- GitLab tokens (`glpat-`, `glrt-`, `gldt-`, `gloas-`)
- Slack bot, user, and app tokens (`xoxb-`, `xoxp-`, `xapp-`) plus webhook URLs
- Discord bot tokens and webhook URLs
- Telegram bot tokens
- SendGrid, Mailgun, Mailchimp, Resend, and Postmark keys
- npm access tokens (`npm_`)
- Stripe live secret, restricted, and webhook keys (`sk_live_`, `rk_live_`, `whsec_`)
- Shopify tokens (`shpat_`, `shpss_`, `shpca_`, `shppa_`)
- Square access tokens (`sq0atp-`, `sq0csp-`)
- Twilio auth tokens
- HuggingFace access tokens (`hf_...`)
- Vercel, Netlify (`nf_`), and DigitalOcean (`dop_v1_`, `doo_v1_`) tokens
- PlanetScale (`pscale_tkn_`), Terraform Cloud (`at.`), Pulumi (`pul-`), Vault (`hvs.`/`hvb.`)
- Supabase service role keys (JWT with `role: service_role`)
- Cloudflare API tokens and global API keys
- Azure storage connection strings and client secrets
- Firebase service account key markers
- Sentry auth tokens (`sntrys_`)
- New Relic (`NRAK-`, `NRAL`) and Datadog API keys
- Notion (`ntn_`), Linear (`lin_api_`), Postman (`PMAK-`), Dropbox (`sl.`), Mapbox (`sk.`)
- Algolia, Contentful, and Heroku API keys
- PyPI API tokens (`pypi-...`)
- Doppler service and personal tokens (`dp.st.`, `dp.pt.`)
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis, AMQP) with a real password. Defaults like `postgres:postgres` and `${DB_PASSWORD}` placeholders are skipped
- RSA, EC, DSA, PKCS8, OpenSSH, and PGP private keys

**Credentials — HIGH**
- JWT tokens (anon and `supabase-demo` keys skipped)
- Stripe live publishable keys (`pk_live_`)
- Google API keys (`AIzaSy...`)
- Firebase web API keys
- Twilio Account SIDs
- GCP service account email markers
- Sentry DSNs
- Generic API keys (high-entropy strings assigned to `api_key`, `API_KEY`, etc.)

**PII — CRITICAL**
- Social Security Numbers (SSN)
- Credit card numbers (Visa, Mastercard, Amex, Discover)

**PII — MEDIUM**
- Email addresses
- US and international phone numbers

**PII — LOW**
- Public IPv4 addresses (private ranges excluded)

All findings are shown **masked** in output — raw secrets are never printed.

## PII and false positives

PII scanning is tuned for production source, not test fixtures.

**Skipped in test-like paths** — email, phone, SSN, credit card, and public IP patterns do not run in:

- `*.test.*`, `*.spec.*`
- `test/`, `tests/`, `__tests__/`, `__mocks__/`
- `fixtures/`, `mocks/`, `stubs/`
- `*.min.js`, `*.min.css`, `*.map`

Paths are checked relative to the scan root, so a parent dir named `test` does not count.

**Filtered fake values** — in other files, obvious placeholders are ignored (e.g. `user@example.com`, `test@test.com`, US `555` numbers, all-same-digit phones). Emails also skip package specs (`slash@3.0.0.js`), `git@` remotes, passwords inside URLs, and published author emails in `package.json`, `LICENSE`, `AUTHORS` and similar files.

**Lockfiles skip PII** — `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` and friends list maintainer emails, so PII patterns do not run there. Credential patterns still do, because private registry URLs can carry tokens.

**Numbers need to look like the real thing:**

- SSNs must be dashed (`123-45-6789`), or have an `ssn` / `social security` label within 40 characters
- Card numbers must pass the Luhn check
- Unformatted 10-digit phone numbers need a label like `phone` or `tel` within 40 characters, and US numbers must be valid NANP
- Digits after a decimal point, inside identifiers, or at the end of longer numbers never match
- Version strings (`Chrome/120.0.0.0`, `v1.2.3.4`), OIDs (`1.3.6.1`), `0.0.0.0` and `169.254.x` are not reported as IP addresses

**Credentials are always scanned** — API keys and tokens in test files are still reported. A real `ghp_` or `sk_live_` in a test is still a leak risk.

`tests/corpus/real-world` holds snippets that tripped earlier versions (math constants, user agents, timestamps, CSS class hashes, lockfiles). CI asserts zero findings on it.

If you only care about credentials, use `--no-pii`.

## Install

```bash
npm install -g secretguard
```

Or use without installing:

```bash
npx secretguard .
```

## Usage

```bash
# Scan current directory
secretguard .

# Scan a specific path or file
secretguard ./src
secretguard src/config.ts

# Ignore additional paths (-i shorthand works too)
secretguard . --ignore tests --ignore fixtures

# Output as JSON
secretguard . --json

# Credentials only, no PII patterns
secretguard . --no-pii

# Fail the run on HIGH or above instead of CRITICAL only
secretguard . --fail-on high

# Also scan files ignored by .gitignore
secretguard . --no-gitignore

# Save HTML report (-o shorthand works too)
secretguard . --output report.html

# Scan full git history
secretguard . --history
secretguard . --history --json

# Scan only staged changes (useful in pre-commit hooks)
secretguard . --staged

# Live-check high-value provider keys (sends candidate secrets to provider APIs)
secretguard . --verify

# Install a git pre-commit hook
secretguard install-hook

# Save SARIF report (for GitHub Code Scanning upload)
secretguard . --sarif results.sarif

# Ignore known findings with a baseline
secretguard . --baseline .secretguard-baseline.json

# Update the baseline to current findings
secretguard . --baseline .secretguard-baseline.json --update-baseline
```

## Network behavior

| Mode | Network | Data sent |
|---|---|---|
| Default scan | None | Nothing |
| `--staged` / `--history` | None | Nothing |
| `--verify` | Provider APIs only | Candidate credential values for supported providers |

`--verify` may contact OpenAI, Anthropic, GitHub, Stripe, and AWS STS. It does **not** upload source files. Do not use `--verify` if that violates your security policy. The CLI prints a warning when `--verify` is enabled.

## Defaults

The following paths are ignored automatically — no configuration needed:

```
node_modules  .git  dist  build  coverage
.next  .nuxt  .turbo  .cache  vendor  __pycache__  .venv
.yarn/releases  .yarn/cache  .pnp.cjs  .pnp.loader.mjs
```

Binary files (images, PDFs, archives, compiled binaries) are skipped automatically.

Inside a git repository, files ignored by your `.gitignore` are skipped too, so a local `.env.local` does not fail the run. Pass `--no-gitignore` to scan them.

Add a `.secretguardignore` file to your project root to ignore additional paths:

```
# .secretguardignore
tests/
fixtures/
src/mocks/
*.min.js
```

Patterns match whole path segments: `tests` skips any `tests/` directory but not `contest/`. A pattern with a `/` is anchored to the scan root, and `*` matches within one segment. The same rules apply to `--ignore`.

## CI/CD

### GitHub Action (recommended)

```yaml
# .github/workflows/secretguard.yml
name: Secret scan
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  secretguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan for secrets
        uses: chintanshah35/secretguard@v1.4.0
        with:
          path: .
          args: --sarif results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

Optional live verification (sends candidate secrets to provider APIs):

```yaml
- uses: chintanshah35/secretguard@v1.4.0
  with:
    path: .
    verify: 'true'
```

### One-liner with npx

```yaml
# GitHub Actions
- name: Scan for secrets
  run: npx secretguard . --ignore tests

# Upload SARIF to GitHub Security tab
- name: Scan and upload SARIF
  run: npx secretguard . --sarif results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

```bash
# Install as a git pre-commit hook
secretguard install-hook
```

The hook runs `secretguard --staged` before each commit and blocks if CRITICAL findings are detected. Use `git commit --no-verify` to bypass.

The exit code is `0` when nothing at or above the `--fail-on` severity (default `critical`) is found, `1` otherwise, and `2` for invalid arguments or a missing path.

## Git history scanning

```bash
# Scan secrets introduced in git commit history (added lines)
secretguard . --history

# Get JSON output (useful for piping)
secretguard . --history --json
```

Scans added lines across commits, deduplicates identical findings (same file + pattern + value across multiple commits), and reports with commit hash, author, date, and message. This is not a full forensic history rewrite analysis.

## Live verification

```bash
secretguard . --verify
```

When `--verify` is set, secretguard calls provider APIs for a small set of high-value secrets:

- OpenAI (`sk-`, `sk-proj-`, `sk-svcacct-`)
- Anthropic (`sk-ant-`)
- GitHub (`ghp_`, `github_pat_`, and related tokens)
- Stripe live secret / restricted keys
- AWS access keys (needs a matching AWS secret key in the same scan)

Findings are marked `confirmed`, `invalid`, `skipped`, `unsupported`, or `error`. Verification is opt-in, needs network access, sends candidate credential values to provider APIs, and is skipped for `--history` scans. See [Network behavior](#network-behavior) and [SECURITY.md](./SECURITY.md).

## Remediation hints

Every finding includes a revoke URL and short next steps in terminal and JSON output so you can rotate the secret without hunting through provider docs.

## Baseline

Use a baseline to suppress findings you've already reviewed and accepted as non-issues:

```bash
# Generate initial baseline from current findings
secretguard . --baseline .secretguard-baseline.json --update-baseline

# On future runs, only new findings are shown
secretguard . --baseline .secretguard-baseline.json
```

Commit `.secretguard-baseline.json` to your repo so the team shares the same suppression list.

## Output formats

**Terminal (default)** — colored output, grouped by severity (CRITICAL first), values masked

**JSON (`--json`)** — structured output with summary counts, useful for piping to other tools

**HTML (`--output report.html`)** — shareable self-contained report with a severity summary and full findings table

**SARIF (`--sarif results.sarif`)** — standard format compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SAST tools

## Programmatic API

```typescript
import { scan, piiPatterns, credentialPatterns } from 'secretguard'
import type { ScanResult, Finding } from 'secretguard'

// Scan with defaults (Finding.raw is omitted)
const result = await scan('./src')

// Scan with options
const result = await scan('./src', {
  ignore: ['tests', 'fixtures'],
  patterns: [...credentialPatterns],  // credentials only, skip PII
})

// Opt in to raw values only when you need them for custom tooling
const withRaw = await scan('./src', { includeRaw: true })

// Inside a git repo, gitignored files are skipped unless you turn it off
const everything = await scan('./src', { gitignore: false })

console.log(result.findings)  // Finding[] (masked only by default)
console.log(result.scanned)   // number of files scanned
console.log(result.duration)  // ms
```

Prefer `masked` in logs. See [SECURITY.md](./SECURITY.md).

## Requirements

Node.js 18 or later.

## Articles

- **[How to Scan for Hardcoded Secrets in a Node.js Project (GitHub Actions Guide)](https://dev.to/chintanshah35/how-to-scan-for-hardcoded-secrets-in-a-nodejs-project-github-actions-guide)** - Dev.to
- **[TruffleHog vs Gitleaks vs GitHub Secret Scanning (2026)](https://dev.to/chintanshah35/trufflehog-vs-gitleaks-vs-github-secret-scanning-why-most-ci-scanners-fail-2026)** - Dev.to

## License

MIT

See [SECURITY.md](./SECURITY.md) for vulnerability reporting and network behavior.
