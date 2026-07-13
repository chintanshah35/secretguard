# secretguard

Scan your source code for secrets, credentials, and PII before they reach production.

```bash
npx secretguard .
```

Exits with code `1` if any CRITICAL findings are detected — drop it into your CI pipeline and it just works.

## What it detects

95 patterns across credentials and PII, grouped by severity.

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
- Supabase service role keys (long JWT)
- Cloudflare API tokens and global API keys
- Azure storage connection strings and client secrets
- Firebase service account key markers
- Sentry auth tokens (`sntrys_`)
- New Relic (`NRAK-`, `NRAL`) and Datadog API keys
- Notion (`ntn_`), Linear (`lin_api_`), Postman (`PMAK-`), Dropbox (`sl.`), Mapbox (`sk.`)
- Algolia, Contentful, and Heroku API keys
- PyPI API tokens (`pypi-...`)
- Doppler service and personal tokens (`dp.st.`, `dp.pt.`)
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis, AMQP — credentials in URL)
- RSA, EC, DSA, PKCS8, OpenSSH, and PGP private keys

**Credentials — HIGH**
- JWT tokens
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
- `__tests__/`, `__mocks__/`
- `fixtures/`, `mocks/`, `stubs/`

**Filtered fake values** — in other files, obvious placeholders are ignored (e.g. `user@example.com`, `test@test.com`, US `555-` numbers, all-same-digit phones).

**Credentials are always scanned** — API keys and tokens in test files are still reported. A real `ghp_` or `sk_live_` in a test is still a leak risk.

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

# Scan a specific path
secretguard ./src

# Ignore additional paths (-i shorthand works too)
secretguard . --ignore tests --ignore fixtures

# Output as JSON
secretguard . --json

# Save HTML report (-o shorthand works too)
secretguard . --output report.html

# Scan full git history
secretguard . --history
secretguard . --history --json

# Scan only staged changes (useful in pre-commit hooks)
secretguard . --staged

# Install a git pre-commit hook
secretguard install-hook

# Save SARIF report (for GitHub Code Scanning upload)
secretguard . --sarif results.sarif

# Ignore known findings with a baseline
secretguard . --baseline .secretguard-baseline.json

# Update the baseline to current findings
secretguard . --baseline .secretguard-baseline.json --update-baseline
```

## Defaults

The following paths are ignored automatically — no configuration needed:

```
node_modules  .git  dist  build  coverage
.next  .nuxt  .turbo  .cache  vendor  __pycache__  .venv
```

Binary files (images, PDFs, archives, compiled binaries) are skipped automatically.

Add a `.secretguardignore` file to your project root to ignore additional paths:

```
# .secretguardignore
tests/
fixtures/
src/mocks/
```

## CI/CD

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

The exit code is `0` when no CRITICAL findings are detected, `1` otherwise.

## Git history scanning

```bash
# Scan all commits in the repo for leaked secrets
secretguard . --history

# Get JSON output (useful for piping)
secretguard . --history --json
```

Scans every added line across every commit, deduplicates identical findings (same file + pattern + value across multiple commits), and reports with commit hash, author, date, and message.

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

// Scan with defaults
const result = await scan('./src')

// Scan with options
const result = await scan('./src', {
  ignore: ['tests', 'fixtures'],
  patterns: [...credentialPatterns],  // credentials only, skip PII
})

console.log(result.findings)  // Finding[]
console.log(result.scanned)   // number of files scanned
console.log(result.duration)  // ms
```

## Requirements

Node.js 18 or later.

## Articles

- **[How to Scan for Hardcoded Secrets in a Node.js Project (GitHub Actions Guide)](https://dev.to/chintanshah35/how-to-scan-for-hardcoded-secrets-in-a-nodejs-project-github-actions-guide)** - Dev.to

## License

MIT
