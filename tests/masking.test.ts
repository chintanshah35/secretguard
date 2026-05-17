import { describe, it, expect } from 'vitest'
import { piiPatterns } from '../src/patterns/pii.js'
import { credentialPatterns } from '../src/patterns/credentials.js'

describe('Masking', () => {
  it('masks email local part', () => {
    const pattern = piiPatterns.find((p) => p.name === 'Email Address')!
    expect(pattern.mask('user@example.com')).toBe('use*@example.com')
    expect(pattern.mask('ab@example.com')).toContain('@example.com')
  })

  it('masks AWS key leaving prefix and suffix', () => {
    const pattern = credentialPatterns.find((p) => p.name === 'AWS Access Key')!
    const masked = pattern.mask('AKIAIOSFODNN7EXAMPLE')
    expect(masked).toContain('AKIA')
    expect(masked).toContain('****')
    expect(masked).not.toContain('SFODNN7EX')
  })

  it('fully redacts private keys', () => {
    const pattern = credentialPatterns.find((p) => p.name === 'RSA Private Key')!
    const key = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----'
    expect(pattern.mask(key)).toContain('[redacted]')
  })

  it('masks credit card leaving last four', () => {
    const pattern = piiPatterns.find((p) => p.name === 'Credit Card')!
    const masked = pattern.mask('4111111111111111')
    expect(masked).toContain('1111')
    expect(masked).toContain('****')
  })
})

describe('Edge cases', () => {
  it('handles empty strings without crashing', () => {
    for (const pattern of piiPatterns) {
      expect(() => pattern.mask('')).not.toThrow()
    }
  })

  it('handles very short strings without crashing', () => {
    for (const pattern of credentialPatterns) {
      expect(() => pattern.mask('ab')).not.toThrow()
    }
  })
})
