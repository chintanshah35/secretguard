import { describe, it, expect } from 'vitest'
import { allPatterns, credentialPatterns } from '../src/patterns/index.js'
import type { PatternMatch } from '../src/patterns/types.js'

// Run a pattern's regex to exhaustion over `text` and return the elapsed milliseconds.
// Times the regex only (no filter), which is where catastrophic backtracking lives.
function regexMs(pattern: RegExp, text: string): number {
  const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g')
  re.lastIndex = 0
  const start = process.hrtime.bigint()
  while (re.exec(text) !== null) {
    if (re.lastIndex === 0) break // non-global safety
  }
  return Number(process.hrtime.bigint() - start) / 1e6
}

// Does the pattern produce a kept finding on `text` (regex match that survives its filter)?
function detects(p: PatternMatch, text: string): boolean {
  const re = new RegExp(p.pattern.source, p.pattern.flags.includes('g') ? p.pattern.flags : p.pattern.flags + 'g')
  re.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const lineStart = text.lastIndexOf('\n', m.index) + 1
    const lineEnd = text.indexOf('\n', m.index)
    const line = text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd)
    if (!p.filter || p.filter(m[0], line, m.index - lineStart)) return true
    if (m.index === re.lastIndex) re.lastIndex++
  }
  return false
}

const ONE_MB = 1_000_000
const repeatTo = (unit: string, size = ONE_MB) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size)

// Adversarial single lines: each is a shape that made an unbounded quantifier backtrack.
const adversarial: Record<string, string> = {
  url_userinfo: repeatTo('postgres://a:'), // URL creds with no @
  at_runs: repeatTo('a@'), // email local@ with no TLD
  pem_begins: repeatTo('-----BEGIN RSA PRIVATE KEY-----\n'), // many BEGIN, no END
  base64: repeatTo('QUJDREVGR0hJSg=='),
  digits: repeatTo('1234567890'),
  dotted_quads: repeatTo('123.'),
  email_ish: repeatTo('aaa.bbb+ccc@ddd-eee.'),
  colons_quotes: repeatTo('ab:cd="ef\'gh'),
}

// Build a secret-shaped block at runtime so no real-looking key lives in the repo.
function base64Body(bytes: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let out = ''
  for (let i = 0; i < bytes; i++) {
    out += chars[(i * 7 + 13) % 64]
    if ((i + 1) % 64 === 0) out += '\n'
  }
  return out + '\n'
}
const pem = (label: string, headers = '') =>
  `-----BEGIN ${label}-----\n${headers}${base64Body(2400)}-----END ${label}-----`

// Linear-time ceiling, not a tuning target. Every pattern is now linear in line length,
// so a 1 MB line finishes in tens of ms. A quadratic regression (the bug this guards) would
// take ~100s on this input — ~300x over this ceiling — so 300ms catches it with huge margin
// while staying immune to slow-CI variance.
const MAX_MS = 300

describe('performance: no pattern backtracks on adversarial 1 MB lines', () => {
  for (const p of allPatterns) {
    for (const [shape, line] of Object.entries(adversarial)) {
      it(`${p.name} on ${shape} < ${MAX_MS}ms`, () => {
        regexMs(p.pattern, 'warmup') // JIT warmup
        const ms = regexMs(p.pattern, line)
        expect(ms, `${p.name} took ${ms.toFixed(1)}ms on ${shape}`).toBeLessThan(MAX_MS)
      })
    }
  }
})

describe('recall: the bounded patterns still catch real keys and credentials', () => {
  const find = (name: string) => {
    const p = credentialPatterns.find((x) => x.name === name)
    if (!p) throw new Error(`pattern not found: ${name}`)
    return p
  }

  it('matches a full RSA private key', () => {
    expect(detects(find('RSA Private Key'), pem('RSA PRIVATE KEY'))).toBe(true)
  })

  it('matches an OpenSSH private key', () => {
    expect(detects(find('OpenSSH Private Key'), pem('OPENSSH PRIVATE KEY'))).toBe(true)
  })

  it('matches a legacy encrypted key with Proc-Type / DEK-Info headers', () => {
    const headers = 'Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6\n\n'
    expect(detects(find('RSA Private Key'), pem('RSA PRIVATE KEY', headers))).toBe(true)
  })

  it('flags a 64-char $-leading DB password (not treated as a placeholder)', () => {
    const pw = '$' + 'Ab12Cd34Ef56Gh78Ij90'.repeat(3) + 'Abc'
    expect(pw.length).toBe(64)
    const url = `postgres://svc:${pw}@db.prod.internal:5432/app`
    expect(detects(find('Database URL (PostgreSQL)'), url)).toBe(true)
  })

  it('still skips a fully-wrapped template password', () => {
    const url = 'postgres://svc:${DB_PASSWORD}@db.prod.internal:5432/app'
    expect(detects(find('Database URL (PostgreSQL)'), url)).toBe(false)
  })
})
