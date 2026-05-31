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
  it('detects email addresses', () => {
    const { pattern } = findPattern(piiPatterns, 'Email Address')
    expect(matches(pattern, 'contact user@example.com today')).toEqual(['user@example.com'])
    expect(matches(pattern, 'no email here')).toEqual([])
  })

  it('detects US phone numbers', () => {
    const { pattern } = findPattern(piiPatterns, 'Phone Number (US)')
    expect(matches(pattern, 'call 555-123-4567 now')).toHaveLength(1)
    expect(matches(pattern, '(555) 123-4567')).toHaveLength(1)
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
