# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.3.x | Yes |
| 1.2.x | Yes (security fixes) |
| < 1.2 | No |

## Reporting a vulnerability

Email the maintainer via the contact listed on [npm package page](https://www.npmjs.com/package/secretguard) or open a **private** GitHub security advisory on [chintanshah35/secretguard](https://github.com/chintanshah35/secretguard).

Please include:
- Affected version
- Reproduction steps
- Impact (secret leak, false negative, supply-chain concern, etc.)

Do not open a public issue for undisclosed vulnerabilities.

## Network and data handling

| Mode | Network | What leaves the machine |
|---|---|---|
| Default scan (`secretguard .`) | None | Nothing |
| `--staged` / `--history` | None (local git only) | Nothing |
| `--verify` | Provider APIs only | Candidate **credential values** for supported patterns |

`--verify` may contact:
- `api.openai.com`
- `api.anthropic.com`
- `api.github.com`
- `api.stripe.com`
- `sts.amazonaws.com` (AWS SigV4)

Source files, repository contents, and unrelated findings are **not** uploaded.

Do not use `--verify` if your organization forbids sending credentials to third-party endpoints for validation.

## Public API and raw secrets

By default, `scan()` omits `Finding.raw` so accidental `console.log(result)` does not dump live secrets.

Pass `{ includeRaw: true }` only when you need the value for custom verification or tooling. Prefer `masked` in logs and reports.

## Threat model (summary)

**In scope**
- Accidental credential / PII commits in working tree, staged diff, or recent history additions
- False positives that train teams to bypass hooks
- Accidental leakage of raw findings through the programmatic API

**Out of scope (for now)**
- Adversarial secret formats designed to evade known regexes
- Full forensic recovery of rewritten / orphaned git objects
- Scanning inside binaries, archives, or container layers
