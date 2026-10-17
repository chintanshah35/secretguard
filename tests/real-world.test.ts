import { describe, it, expect } from 'vitest'
import { mkdir, mkdtemp, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { scan } from '../src/scanner/index.js'

const corpus = join(dirname(fileURLToPath(import.meta.url)), 'corpus', 'real-world')

describe('Real-world false positives', () => {
  it('finds nothing in the corpus', async () => {
    const result = await scan(corpus)

    expect(result.scanned).toBe(7)
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

  it('reports database URLs with real passwords', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-'))
    const url = ['postgres://app', 'Xk9mP2vQ8zLw@prod.internal.dev/app'].join(':')
    await writeFile(join(directory, 'db.ts'), `export const url = '${url}'`)

    const result = await scan(directory)

    expect(result.findings.map((finding) => finding.pattern)).toEqual(['Database URL (PostgreSQL)'])
  })

  it('still finds PII when a parent dir is named test', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'secretguard-'))
    const directory = join(parent, 'test', 'app')
    await mkdir(directory, { recursive: true })
    await writeFile(join(directory, 'users.ts'), `const owner = 'jane.smith@acme-corp.io'`)

    const result = await scan(directory)

    expect(result.findings.map((finding) => finding.pattern)).toEqual(['Email Address'])
  })
})

describe('JWTs', () => {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const jwt = (payload: object) =>
    ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', encode(payload), 's'.repeat(43)].join('.')

  const patternsFor = async (token: string) => {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-'))
    await writeFile(join(directory, 'env.ts'), `export const key = '${token}'`)
    const result = await scan(directory)
    return result.findings.map((finding) => finding.pattern).sort()
  }

  const project = { iss: 'supabase', ref: 'abcdefghijklmnopqrst', iat: 1700000000, exp: 2000000000 }

  it('flags Supabase service role keys', async () => {
    expect(await patternsFor(jwt({ ...project, role: 'service_role' }))).toEqual([
      'JWT Token',
      'Supabase Service Role Key',
    ])
  })

  it('skips anon keys', async () => {
    expect(await patternsFor(jwt({ ...project, role: 'anon' }))).toEqual([])
  })

  it('skips supabase-demo keys', async () => {
    expect(await patternsFor(jwt({ iss: 'supabase-demo', role: 'service_role', exp: 1983812996 }))).toEqual([])
  })
})

describe('Targets', () => {
  it('scans a single file', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-'))
    const file = join(directory, 'leak.ts')
    await writeFile(file, `const token = '${['ghp', 'a'.repeat(36)].join('_')}'`)

    const result = await scan(file)

    expect(result.scanned).toBe(1)
    expect(result.findings.map((finding) => finding.pattern)).toEqual(['GitHub Personal Access Token'])
  })

  it('rejects a missing path', async () => {
    await expect(scan('/does/not/exist')).rejects.toThrow('Path not found')
  })
})
