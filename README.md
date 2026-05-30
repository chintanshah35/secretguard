# secretscan

Scan your source code for secrets, credentials, and PII before they reach production.

```bash
npx secretscan .
```

Exits with code `1` if any CRITICAL findings are detected — drop it into your CI pipeline and it just works.

## What it detects

**Credentials — CRITICAL**
- AWS access keys (`AKIA...`) and secret keys
- GitHub tokens (`ghp_`, `ghs_`, `gho_`)
- Stripe live secret keys (`sk_live_`)
- RSA, EC, and OpenSSH private keys

**Credentials — HIGH**
- JWT tokens
- Stripe live publishable keys (`pk_live_`)
- Generic API keys (high-entropy strings assigned to `api_key`, `API_KEY`, etc.)

**PII — MEDIUM**
- Email addresses
- US and international phone numbers
- Social Security Numbers (SSN)
- Credit card numbers (Visa, Mastercard, Amex, Discover)

All findings are shown **masked** in output — raw secrets are never printed.

## Install

```bash
npm install -g secretscan
```

Or use without installing:

```bash
npx secretscan .
```

## Usage

```bash
# Scan current directory
secretscan .

# Scan a specific path
secretscan ./src

# Ignore additional paths (repeatable, -i shorthand works too)
secretscan . --ignore tests --ignore fixtures
secretscan . -i tests -i fixtures

# Output as JSON
secretscan . --json

# Save HTML report (-o shorthand works too)
secretscan . --output report.html
secretscan . -o report.html

# Combine flags
secretscan . -i tests --json
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
  run: npx secretscan . --ignore tests
```

```bash
# Pre-commit hook (in .git/hooks/pre-commit)
secretscan . && git commit
```

The exit code is `0` when no CRITICAL findings are detected, `1` otherwise. This makes it straightforward to block CI on real secrets while still reporting HIGH/MEDIUM findings.

## Output formats

**Terminal (default)** — colored output, grouped by severity (CRITICAL first), values masked

**JSON (`--json`)** — structured output with summary counts, useful for piping to other tools or parsing in scripts

**HTML (`--output report.html`)** — shareable self-contained report with a severity summary and full findings table

## Programmatic API

```typescript
import { scan, piiPatterns, credentialPatterns } from 'secretscan'
import type { ScanResult, Finding } from 'secretscan'

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

## License

MIT
