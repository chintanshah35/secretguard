import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile, mkdir } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { scan } from '../src/scanner/index.js'
import { withoutRaw } from '../src/sanitize.js'
import type { Finding } from '../src/patterns/types.js'

describe('withoutRaw', () => {
  it('removes raw from findings', () => {
    const findings: Finding[] = [
      {
        file: 'a.ts',
        line: 1,
        column: 1,
        pattern: 'OpenAI API Key',
        severity: 'CRITICAL',
        masked: 'sk-****',
        raw: 'sk-secretvalue',
      },
    ]
    const safe = withoutRaw(findings)
    expect(safe[0]?.raw).toBeUndefined()
    expect(safe[0]?.masked).toBe('sk-****')
  })
})

describe('scan includeRaw', () => {
  it('omits raw by default', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'secretguard-raw-'))
    await mkdir(join(dir, 'src'))
    await writeFile(
      join(dir, 'src', 'keys.ts'),
      `const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n`,
      'utf-8',
    )

    const result = await scan(dir)
    const github = result.findings.find((finding) => finding.pattern.includes('GitHub'))
    expect(github).toBeDefined()
    expect(github?.raw).toBeUndefined()
    expect(github?.masked).toBeTruthy()
  })

  it('includes raw when includeRaw is true', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'secretguard-raw-'))
    await mkdir(join(dir, 'src'))
    await writeFile(
      join(dir, 'src', 'keys.ts'),
      `const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'\n`,
      'utf-8',
    )

    const result = await scan(dir, { includeRaw: true })
    const github = result.findings.find((finding) => finding.pattern.includes('GitHub'))
    expect(github?.raw).toContain('ghp_')
  })
})
