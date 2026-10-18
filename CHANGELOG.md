# Changelog

## 1.4.0

Far fewer false positives on real code. Benchmarked across a range of large open-source projects, 1.4.0 reports dramatically fewer findings than 1.3.0 and no critical false positives, and produces valid JSON even on large result sets. The findings it keeps are benign lower-severity matches that are correctly flagged, not suppressed.

### Breaking-ish
- Inside a git repo, files ignored by `.gitignore` are no longer scanned. Use `--no-gitignore` (or `gitignore: false`) to scan them
- `--ignore` and `.secretguardignore` match whole path segments: `test` no longer skips `contest/` or `latest.ts`, and `.env` no longer skips `.env.local` (use `.env*`)
- Unknown flags and flags missing a value exit with code 2 instead of being ignored
- PII patterns skip `test/` and `tests/` dirs, `*.min.js`, `*.min.css` and `*.map`. Credentials are still checked there
- `.yarn/releases`, `.yarn/cache` and `.pnp.*` are ignored by default
- A missing scan path exits with code 2 and a one-line error
- An unexpected internal error now exits with code 3, distinct from findings (1) and usage errors (2), so CI can tell a broken scan apart from a scan that found secrets. Exit codes are documented in `--help`

### Added
- `--no-pii` to scan credentials only
- `--fail-on <low|medium|high|critical>` to choose the severity that fails the run (default critical)
- `*` wildcards in ignore patterns (`*.min.js`)
- Scanning a single file: `secretguard src/config.ts`
- Self-scan dogfood: `secretguard .` runs clean against a committed `.secretguard-baseline.json` (the repo's own regex literals and documentation examples), enforced in CI. New test fixtures generate secret-shaped strings at runtime rather than committing them

### Fixed
- Email pattern backtracked quadratically on long lines; a 1 MB minified line could hang CI for minutes
- Credential URL patterns (postgres, mysql, mongodb, redis, amqp) and the six private-key patterns also backtracked quadratically — a large line could take minutes. All are now linear, held to a fixed ceiling by a CI performance test. Legacy encrypted keys (`Proc-Type` / `DEK-Info`) are still matched
- Passwords beginning with `$` or `<` were treated as placeholders and silently skipped, missing real credentials. Only fully-wrapped templates (`${…}`, `<…>`, `{{…}}`, `***`, `xxx`) are skipped now
- URL passwords containing `! # & $ <` no longer produce a spurious Email finding
- Docker/image tags like `postgres:15.8.1.100` are no longer reported as IPv4 addresses
- SSN: bare 9-digit numbers need an `ssn` / `social security` label within 40 characters; digits after a decimal point never match
- Credit cards: Luhn check, and no matches after a decimal point
- US phone: no matches on the tail of longer numbers or inside identifiers; unformatted 10-digit runs need a phone label within 40 characters; invalid NANP numbers and the fictional 555 exchange are skipped
- IPv4: skips version strings like `Chrome/120.0.0.0`, `v1.2.3.4`, `1.2.3.4.5`, plus `0.x`, link-local `169.254.x`, broadcast, and OIDs or section numbers made of small octets
- Email: skips package specs (`slash@3.0.0.js`), `git@` remotes, subdomains of example domains, URL passwords, and author emails in `package.json`, `LICENSE`, `AUTHORS` and similar files
- Supabase Service Role Key only fires on JWTs whose role is `service_role`. Anon keys and the CLI's `supabase-demo` keys are skipped, also by the generic JWT rule
- Database URLs with default or placeholder passwords (`postgres:postgres`, `app:app`, `${DB_PASSWORD}`) are skipped
- File skip rules are checked relative to the scan root, so scanning `~/test/app` no longer disables PII rules. Single-file scans use the working directory as that root, so `secretguard tests/fixture.ts` applies the same `tests/` skip as a directory scan
- An unreadable directory (e.g. `EACCES`) is now skipped with a one-line warning instead of crashing the scan
- Explicitly naming a gitignored directory scans it (with a note on stderr), the same way naming a single gitignored file already did
- Lockfiles skip PII patterns; `yarn.lock` is now scanned for credentials (it was treated as binary)
- `--history` respects per-pattern file skips
- `--json` output was cut off at 64 KB when piped and findings existed
- GitHub Action passes inputs through `env` instead of interpolating them into the script. Note: Action `args` are split on whitespace and passed as separate arguments, with no quote handling (write `args: --ignore *.min.js`, not quoted)

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
