import { describe, it, expect } from 'vitest'
import { piiPatterns } from '../src/patterns/pii.js'
import { credentialPatterns } from '../src/patterns/credentials.js'

function findPattern(patterns: typeof piiPatterns, name: string) {
  const pattern = patterns.find((p) => p.name === name)
  if (!pattern) throw new Error(`Pattern not found: ${name}`)
  return pattern
}

function matches(pattern: RegExp, input: string): string[] {
  pattern.lastIndex = 0
  const results: string[] = []
  let match: RegExpExecArray | null
  while ((match = pattern.exec(input)) !== null) {
    results.push(match[0])
  }
  return results
}

describe('PII patterns', () => {
  it('detects real email addresses', () => {
    const entry = findPattern(piiPatterns, 'Email Address')
    const real = matches(entry.pattern, 'contact chintan@gmail.com today')
    expect(real.filter((m) => entry.filter!(m))).toHaveLength(1)
  })

  it('filters fake email domains', () => {
    const entry = findPattern(piiPatterns, 'Email Address')
    const fakes = ['user@example.com', 'test@test.com', 'admin@localhost', 'foo@foo.com']
    for (const email of fakes) {
      expect(entry.filter!(email)).toBe(false)
    }
  })

  it('detects real US phone numbers', () => {
    const entry = findPattern(piiPatterns, 'Phone Number (US)')
    expect(entry.filter!('415-823-9147')).toBe(true)
  })

  it('filters fake US phone numbers', () => {
    const entry = findPattern(piiPatterns, 'Phone Number (US)')
    expect(entry.filter!('555-123-4567')).toBe(false)
    expect(entry.filter!('1234567890')).toBe(false)
    expect(entry.filter!('1111111111')).toBe(false)
  })

  it('skips PII patterns in test and fixture files', () => {
    const entry = findPattern(piiPatterns, 'Email Address')
    expect(entry.skipFiles!.test('/src/auth.test.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/__tests__/auth.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/fixtures/users.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/mocks/data.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/auth.ts')).toBe(false)
    expect(entry.skipFiles!.test('/src/controllers/user.ts')).toBe(false)
  })

  it('detects SSNs', () => {
    const { pattern } = findPattern(piiPatterns, 'SSN')
    expect(matches(pattern, 'ssn: 123-45-6789')).toHaveLength(1)
    expect(matches(pattern, 'ssn: 000-45-6789')).toHaveLength(0)
  })

  it('detects credit cards', () => {
    const { pattern } = findPattern(piiPatterns, 'Credit Card')
    expect(matches(pattern, '4111 1111 1111 1111')).toHaveLength(1)
    expect(matches(pattern, '5500-0000-0000-0004')).toHaveLength(1)
  })
})

describe('Credential patterns', () => {
  it('detects AWS access keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'AWS Access Key')
    expect(matches(pattern, 'AKIAIOSFODNN7EXAMPLE')).toHaveLength(1)
    expect(matches(pattern, 'not-an-aws-key')).toHaveLength(0)
  })

  it('detects GitHub tokens', () => {
    const ghp = findPattern(credentialPatterns, 'GitHub Personal Access Token')
    // ghp_ + exactly 36 alphanumeric chars
    expect(matches(ghp.pattern, 'ghp_abcdefghijklmnopqrstuvwxyz1234567890')).toHaveLength(1)
    expect(matches(ghp.pattern, 'ghp_tooshort')).toHaveLength(0)
  })

  it('detects Stripe live keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Stripe Live Secret Key')
    // Constructed dynamically — never stored as a literal to avoid false positives in scanners
    const fakeKey = ['sk', 'live', 'a'.repeat(24)].join('_')
    expect(matches(pattern, fakeKey)).toHaveLength(1)
    expect(matches(pattern, 'sk_test_notlive')).toHaveLength(0)
  })
})
