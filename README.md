# secretguard

Scan your source code for secrets, credentials, and PII before they reach production.

```bash
npx secretguard .
```

Exits with code `1` if any CRITICAL findings are detected — drop it into your CI pipeline and it just works.

## What it detects

46 patterns across credentials and PII, grouped by severity.

**Credentials — CRITICAL**
- AWS access keys (`AKIA...`) and secret keys
- OpenAI API keys (`sk-...`)
- Anthropic API keys (`sk-ant-...`)
- GitHub tokens (`ghp_`, `ghs_`, `gho_`, `github_pat_`)
- GitLab personal access tokens (`glpat-`)
- Slack bot and user tokens (`xoxb-`, `xoxp-`)
- SendGrid API keys (`SG.`)
- npm access tokens (`npm_`)
- Stripe live secret keys (`sk_live_`)
- Twilio auth tokens
- HuggingFace access tokens (`hf_...`)
- Vercel access tokens
- Supabase service role keys (long JWT)
- Cloudflare API tokens and global API keys
- Azure storage connection strings and client secrets
- Firebase service account key markers
- PyPI API tokens (`pypi-...`)
- Doppler service and personal tokens (`dp.st.`, `dp.pt.`)
- Database URLs (PostgreSQL, MySQL, MongoDB — credentials in URL)
- RSA, EC, OpenSSH, and PGP private keys

**Credentials — HIGH**
- JWT tokens
- Stripe live publishable keys (`pk_live_`)
- Google API keys (`AIzaSy...`)
- Firebase web API keys
- Twilio Account SIDs
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

# Ignore additional paths (repeatable, -i shorthand works too)
secretguard . --ignore tests --ignore fixtures
secretguard . -i tests -i fixtures

# Output as JSON
secretguard . --json

# Save HTML report (-o shorthand works too)
secretguard . --output report.html
secretguard . -o report.html

# Combine flags
secretguard . -i tests --json
```

## Defaults

The following paths are ignored automatically — no configuration needed:

```
node_modules  .git  dist  build  coverage
.next  .nuxt  .turbo  .cache  vendor  __pycache__  .venv
```

Binary files (images, PDFs, archives, compiled binaries) are skipped automatically.

## CI/CD

```yaml
# GitHub Actions
- name: Scan for secrets and PII
  run: npx secretguard . --ignore tests
```

```bash
# Pre-commit hook (in .git/hooks/pre-commit)
secretguard . && git commit
```

The exit code is `0` when no CRITICAL findings are detected, `1` otherwise. This makes it straightforward to block CI on real secrets while still reporting HIGH/MEDIUM findings.

## Output formats

**Terminal (default)** — colored output, grouped by severity (CRITICAL first), values masked

**JSON (`--json`)** — structured output with summary counts, useful for piping to other tools or parsing in scripts

**HTML (`--output report.html`)** — shareable self-contained report with a severity summary and full findings table

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
