import { describe, it, expect } from 'vitest'
import { execFileSync } from 'child_process'
import { mkdtemp, writeFile, mkdir } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { isIgnored } from '../src/scanner/ignore.js'
import { scan } from '../src/scanner/index.js'

describe('isIgnored', () => {
  it('matches whole segments, not substrings', () => {
    expect(isIgnored('test/auth.ts', ['test'])).toBe(true)
    expect(isIgnored('src/contest/entry.ts', ['test'])).toBe(false)
    expect(isIgnored('src/latest.ts', ['test'])).toBe(false)
  })

  it('treats a trailing slash like gitignore', () => {
    expect(isIgnored('packages/api/tests/auth.ts', ['tests/'])).toBe(true)
  })

  it('anchors patterns that contain a slash', () => {
    expect(isIgnored('src/mocks/user.ts', ['src/mocks'])).toBe(true)
    expect(isIgnored('lib/src/mocks/user.ts', ['src/mocks'])).toBe(false)
  })

  it('supports * within a segment', () => {
    expect(isIgnored('public/app.min.js', ['*.min.js'])).toBe(true)
    expect(isIgnored('public/app.js', ['*.min.js'])).toBe(false)
    expect(isIgnored('.env.local', ['.env*'])).toBe(true)
  })

  it('handles windows separators', () => {
    expect(isIgnored('src\\fixtures\\user.ts', ['fixtures'])).toBe(true)
  })
})

describe('gitignore', () => {
  const secret = ['ghp', 'a'.repeat(36)].join('_')

  async function repoWithIgnoredSecret() {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-git-'))
    execFileSync('git', ['init', '-q'], { cwd: directory })
    await writeFile(join(directory, '.gitignore'), '.env.local\nlogs/\n')
    await writeFile(join(directory, '.env.local'), `GITHUB_TOKEN=${secret}\n`)
    await mkdir(join(directory, 'logs'))
    await writeFile(join(directory, 'logs', 'debug.log'), `token ${secret}\n`)
    await writeFile(join(directory, 'index.ts'), `export const ok = true\n`)
    return directory
  }

  it('skips files git ignores', async () => {
    const result = await scan(await repoWithIgnoredSecret())

    expect(result.findings).toEqual([])
    expect(result.scanned).toBe(2)
  })

  it('scans them with gitignore: false', async () => {
    const result = await scan(await repoWithIgnoredSecret(), { gitignore: false })

    expect(result.findings.map((finding) => finding.file).sort()).toEqual([
      expect.stringContaining('.env.local'),
      expect.stringContaining('debug.log'),
    ])
  })

  it('scans an explicitly named gitignored directory (and still skips it under a parent scan)', async () => {
    const directory = await repoWithIgnoredSecret()

    // Scanning the repo root skips logs/ (gitignored)
    const parent = await scan(directory)
    expect(parent.findings).toEqual([])

    // Naming the ignored directory explicitly scans it anyway
    const explicit = await scan(join(directory, 'logs'))
    expect(explicit.findings.map((finding) => finding.file)).toEqual([
      expect.stringContaining('debug.log'),
    ])
  })

  it('walks everything outside a git repo', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'secretguard-plain-'))
    await writeFile(join(directory, '.env.local'), `GITHUB_TOKEN=${secret}\n`)

    const result = await scan(directory)

    expect(result.findings).toHaveLength(1)
  })
})
