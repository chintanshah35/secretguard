import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { scan } from '../src/scanner/index.js'

const corpus = join(dirname(fileURLToPath(import.meta.url)), 'corpus', 'real-world')

describe('Real-world false positives', () => {
  it('finds nothing in the corpus', async () => {
    const result = await scan(corpus)

    expect(result.scanned).toBe(5)
    expect(result.findings).toEqual([])
  })
})

describe('Real leaks', () => {
  it('still reports actual PII', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-'))
    await writeFile(join(directory, 'customers.ts'), [
      `const ssn = '123-45-6789'`,
      `const legacy = '123456789' // ssn`,
      `const card = '4111 1111 1111 1111'`,
      `const support = '(415) 823-9147'`,
      `const upstream = '34.120.5.9'`,
    ].join('\n'))

    const result = await scan(directory)
    const found = result.findings.map((finding) => finding.pattern).sort()

    expect(found).toEqual(['Credit Card', 'IPv4 Address', 'Phone Number (US)', 'SSN', 'SSN'])
  })

  it('scans lockfiles for credentials but not PII', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-'))
    const token = ['npm', 'a'.repeat(36)].join('_')
    await writeFile(join(directory, 'yarn.lock'), [
      `"private-pkg@^1.0.0":`,
      `  resolved "https://registry.internal.dev/private-pkg/-/private-pkg-1.0.0.tgz?token=${token}"`,
      `  maintainer "Real Person <someone@company-internal.dev>"`,
    ].join('\n'))

    const result = await scan(directory)

    expect(result.findings.map((finding) => finding.pattern)).toEqual(['npm Access Token'])
  })
})
