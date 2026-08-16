import { describe, it, expect } from 'vitest'
import { getRemediation } from '../src/remediation.js'
import { withRemediation } from '../src/enrich.js'
import { credentialPatterns } from '../src/patterns/credentials.js'
import type { Finding } from '../src/patterns/types.js'

describe('remediation', () => {
  it('returns revoke guidance for OpenAI keys', () => {
    const remediation = getRemediation('OpenAI API Key')
    expect(remediation?.revokeUrl).toContain('openai.com')
    expect(remediation?.steps.length).toBeGreaterThan(0)
  })

  it('covers every credential pattern name', () => {
    const missing = credentialPatterns
      .map((pattern) => pattern.name)
      .filter((name) => !getRemediation(name))
    expect(missing).toEqual([])
  })

  it('covers every pii pattern name', async () => {
    const { piiPatterns } = await import('../src/patterns/pii.js')
    const missing = piiPatterns
      .map((pattern) => pattern.name)
      .filter((name) => !getRemediation(name))
    expect(missing).toEqual([])
  })

  it('attaches remediation onto findings', () => {
    const findings: Finding[] = [
      {
        file: 'app.ts',
        line: 1,
        column: 1,
        pattern: 'GitHub Personal Access Token',
        severity: 'CRITICAL',
        masked: 'ghp_****',
        raw: 'ghp_exampletokenvalue000000000000000',
      },
    ]
    const enriched = withRemediation(findings)
    expect(enriched[0]?.remediation?.revokeUrl).toContain('github.com')
  })
})
