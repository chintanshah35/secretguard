# Changelog

## 1.4.0

Fewer false positives on real code. The published 1.3.0 reports 19 findings (6 CRITICAL) on `tests/corpus/real-world`; 1.4.0 reports none.

### Breaking-ish
- Inside a git repo, files ignored by `.gitignore` are no longer scanned. Use `--no-gitignore` (or `gitignore: false`) to scan them
- `--ignore` and `.secretguardignore` match whole path segments: `test` no longer skips `contest/` or `latest.ts`, and `.env` no longer skips `.env.local` (use `.env*`)
- Unknown flags and flags missing a value exit with code 2 instead of being ignored

### Added
- `--no-pii` to scan credentials only
- `--fail-on <low|medium|high|critical>` to choose the severity that fails the run (default critical)
- `*` wildcards in ignore patterns (`*.min.js`)

### Fixed
- SSN: bare 9-digit numbers need an `ssn` / `social security` label on the line; digits after a decimal point never match
- Credit cards: Luhn check, and no matches after a decimal point
- US phone: no matches on the tail of longer numbers or inside identifiers; unformatted 10-digit runs need a phone label
- IPv4: skips version strings like `Chrome/120.0.0.0`, `v1.2.3.4`, `version 4.12.3.1`, `1.2.3.4.5`
- Lockfiles skip PII patterns; `yarn.lock` is now scanned for credentials (it was treated as binary)
- `--history` respects per-pattern file skips
- `--json` output was cut off at 64 KB when piped and findings existed
- GitHub Action passes inputs through `env` instead of interpolating them into the script

## 1.3.0

### Added
- Network behavior docs and CLI warning for `--verify`
- `SECURITY.md` with disclosure and data-handling policy
- GitHub Action (`action.yml`) for CI workflows
- `includeRaw` scan option (default off)
- `withoutRaw()` helper for stripping secret values

### Changed
- `Finding.raw` is optional and omitted from `scan()` / `scanStaged()` by default
- CLI keeps raw in memory only long enough for `--verify`, then strips before output
- README clarifies pattern coverage and history-scan scope

## 1.2.0

### Added
- Live verification (`--verify`) for OpenAI, Anthropic, GitHub, Stripe, and AWS
- Remediation revoke URLs and next steps on findings
- Programmatic `verifyFindings`, `canVerify`, `getRemediation` exports

See `RELEASE_NOTES_v1.2.0.md` for detail.

## 1.1.0 and earlier

Baseline scanning, SARIF/HTML/JSON reporters, staged and history modes, pre-commit hook installer, and credential/PII pattern set.
