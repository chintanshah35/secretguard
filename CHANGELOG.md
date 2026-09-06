# Changelog

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
