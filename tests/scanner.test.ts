import { describe, it, expect } from 'vitest'
import { mkdtemp, writeFile, mkdir, chmod } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { scan } from '../src/scanner/index.js'

const secret = ['ghp', 'a'.repeat(36)].join('_')
const email = 'alex.kim@realcorp.io'

describe('single-file scan applies the same skip rules as a directory scan', () => {
  it('skips PII in a tests/ file but still scans a src/ file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'secretguard-single-'))
    await mkdir(join(dir, 'tests'))
    await mkdir(join(dir, 'src'))
    await writeFile(join(dir, 'tests', 'fixture.ts'), `const contact = "${email}"\n`)
    await writeFile(join(dir, 'src', 'app.ts'), `const contact = "${email}"\n`)

    const inTests = await scan(join(dir, 'tests', 'fixture.ts'))
    expect(inTests.findings.filter((f) => f.pattern === 'Email Address')).toEqual([])

    const inSrc = await scan(join(dir, 'src', 'app.ts'))
    expect(inSrc.findings.filter((f) => f.pattern === 'Email Address')).toHaveLength(1)
  })
})

// chmod 000 is meaningless on Windows and ineffective as root.
const canTestPerms = process.platform !== 'win32' && (process.getuid?.() ?? 0) !== 0

describe('scan survives an unreadable directory', () => {
  it.skipIf(!canTestPerms)('skips it with a warning instead of crashing', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'secretguard-perm-'))
    await writeFile(join(dir, 'ok.ts'), `const t = "${secret}"\n`)
    await mkdir(join(dir, 'locked'))
    await writeFile(join(dir, 'locked', 'inner.ts'), `const t = "${secret}"\n`)
    await chmod(join(dir, 'locked'), 0o000)
    try {
      const result = await scan(dir, { gitignore: false })
      // Completed without throwing, and the readable file was still scanned.
      expect(result.findings.some((f) => f.file.includes('ok.ts'))).toBe(true)
    } finally {
      await chmod(join(dir, 'locked'), 0o755) // let temp cleanup remove it
    }
  })
})
