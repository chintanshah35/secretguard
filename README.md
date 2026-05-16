# secretscan

Scan your source code for secrets, credentials, and PII before they reach production.

```bash
npx secretscan .
```

## What it detects

**Credentials (CRITICAL/HIGH)**
- AWS access keys and secret keys
- GitHub personal access, app, and OAuth tokens
- Stripe live secret and publishable keys
- JWT tokens
- RSA, EC, and OpenSSH private keys
- Generic API keys

**PII (MEDIUM)**
- Email addresses
- US and international phone numbers
- Social Security Numbers (SSN)
- Credit card numbers

## Install

```bash
npm install -g secretscan
# or use without installing
npx secretscan .
```

## Usage

```bash
# Scan current directory
secretscan .

# Scan a specific path
secretscan ./src

# Ignore additional directories
secretscan . --ignore tests --ignore fixtures

# Output as JSON (useful for CI)
secretscan . --json

# Save HTML report
secretscan . --output report.html
```

## CI/CD

secretscan exits with code `1` if any CRITICAL findings are detected, making it easy to fail CI pipelines.

```yaml
# GitHub Actions
- name: Scan for secrets
  run: npx secretscan . --ignore node_modules
```

## License

MIT
