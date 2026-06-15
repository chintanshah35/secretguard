import { describe, it, expect } from 'vitest'
import { readFile, writeFile, unlink } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { piiPatterns } from '../src/patterns/pii.js'
import { credentialPatterns } from '../src/patterns/credentials.js'
import { loadIgnoreFile } from '../src/scanner/ignorefile.js'

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

  it('detects HuggingFace access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'HuggingFace Access Token')
    const token = 'hf_' + 'a'.repeat(34)
    expect(matches(pattern, `HF_TOKEN="${token}"`)).toHaveLength(1)
    expect(matches(pattern, 'hf_short')).toHaveLength(0)
  })

  it('detects Vercel access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Vercel Access Token')
    expect(matches(pattern, 'VERCEL_TOKEN="aBcDeFgHiJkLmNoPqRsTuVwX"')).toHaveLength(1)
    expect(matches(pattern, 'VERCEL_TOKEN="tooshort"')).toHaveLength(0)
  })

  it('detects Supabase service role JWTs', () => {
    const { pattern } = findPattern(credentialPatterns, 'Supabase Service Role Key')
    const header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    const payload = 'e'.repeat(70)
    const sig = 'f'.repeat(43)
    expect(matches(pattern, `${header}.${payload}.${sig}`)).toHaveLength(1)
  })

  it('detects Cloudflare API tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Cloudflare API Token')
    expect(matches(pattern, `CF_API_TOKEN="${'a'.repeat(40)}"`)).toHaveLength(1)
  })

  it('detects Azure storage connection strings', () => {
    const { pattern } = findPattern(credentialPatterns, 'Azure Storage Connection String')
    const key = 'A'.repeat(86) + '=='
    const conn = `DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=${key};EndpointSuffix=core.windows.net`
    expect(matches(pattern, conn)).toHaveLength(1)
  })

  it('detects PyPI API tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'PyPI API Token')
    const token = 'pypi-' + 'A'.repeat(50)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'pypi-tooshort')).toHaveLength(0)
  })

  it('detects Doppler service tokens', () => {
    const service = findPattern(credentialPatterns, 'Doppler Service Token')
    const token = 'dp.st.dev.' + 'A'.repeat(40)
    expect(matches(service.pattern, token)).toHaveLength(1)

    const personal = findPattern(credentialPatterns, 'Doppler Personal Token')
    const ptoken = 'dp.pt.' + 'A'.repeat(40)
    expect(matches(personal.pattern, ptoken)).toHaveLength(1)
  })

  it('detects Firebase service account key markers', () => {
    const { pattern } = findPattern(credentialPatterns, 'Firebase Service Account Key')
    const keyId = '"private_key_id": "' + 'a'.repeat(40) + '"'
    expect(matches(pattern, keyId)).toHaveLength(1)
  })
})

describe('Ignorefile', () => {
  it('loads patterns from .secretguardignore', async () => {
    const dir = tmpdir()
    const filePath = join(dir, '.secretguardignore')
    await writeFile(filePath, '# comment\nnode_modules\ndist\n\n.env\n', 'utf-8')
    const patterns = await loadIgnoreFile(dir)
    expect(patterns).toEqual(['node_modules', 'dist', '.env'])
    await unlink(filePath)
  })

  it('returns empty array when file is missing', async () => {
    const patterns = await loadIgnoreFile('/tmp/does-not-exist-secretguard-test')
    expect(patterns).toEqual([])
  })
})
