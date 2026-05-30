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
- Stripe live keys (`sk_live_`, `pk_live_`)
- RSA, EC, and OpenSSH private keys

**Credentials — HIGH**
- JWT tokens
- Generic API keys (high-entropy strings assigned to `api_key`, `API_KEY`, etc.)

**PII — MEDIUM**
- Email addresses
- US and international phone numbers
- Social Security Numbers
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

# Ignore additional paths (repeatable)
secretscan . --ignore tests --ignore fixtures --ignore __mocks__

# Output as JSON
secretscan . --json

# Save HTML report
secretscan . --output report.html

# Combine flags
secretscan . --ignore tests --json
```

## CI/CD

```yaml
# GitHub Actions
- name: Scan for secrets and PII
  run: npx secretscan . --ignore node_modules --ignore dist
```

```bash
# Pre-commit hook
secretscan . && git commit
```

## Programmatic API

```typescript
import { scan } from 'secretscan'

const result = await scan('./src', {
  ignore: ['tests'],
})

console.log(result.findings)   // Finding[]
console.log(result.scanned)    // number of files scanned
console.log(result.duration)   // ms
```

## Output formats

**Terminal (default)** — colored, grouped by severity, values masked

**JSON (`--json`)** — structured output with summary counts, for piping to other tools

**HTML (`--output report.html`)** — shareable report with a findings table and severity summary

## License

MIT
