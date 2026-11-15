import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtemp, mkdir, writeFile, chmod, rm } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { runAudit } from '../src/audit/index.js'

let home: string
let target: string

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), 'sg-audit-home-'))
  target = await mkdtemp(join(tmpdir(), 'sg-audit-proj-'))
})

afterEach(async () => {
  await rm(home, { recursive: true, force: true })
  await rm(target, { recursive: true, force: true })
})

const run = () => runAudit({ home, target, platform: 'linux' })
const ids = (findings: { id: string }[]) => findings.map((f) => f.id)

describe('runAudit', () => {
  it('reports no findings for a clean home and empty project', async () => {
    const result = await run()
    expect(result.findings).toEqual([])
    expect(result.checked).toBeGreaterThan(0)
  })

  it('flags an npm auth token in ~/.npmrc', async () => {
    await writeFile(join(home, '.npmrc'), '//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop\n')
    const { findings } = await run()
    expect(ids(findings)).toContain('npm-token-on-disk')
    expect(findings.find((f) => f.id === 'npm-token-on-disk')?.severity).toBe('HIGH')
  })

  it('does not flag an ~/.npmrc without a token', async () => {
    await writeFile(join(home, '.npmrc'), 'registry=https://registry.npmjs.org/\nsave-exact=true\n')
    expect(ids((await run()).findings)).not.toContain('npm-token-on-disk')
  })

  it('flags static AWS keys and raises severity on loose permissions', async () => {
    await mkdir(join(home, '.aws'))
    const path = join(home, '.aws', 'credentials')
    await writeFile(path, '[default]\naws_access_key_id=AKIA...\naws_secret_access_key=secret\n')
    await chmod(path, 0o644) // group/other readable
    const finding = (await run()).findings.find((f) => f.id === 'aws-static-keys')
    expect(finding?.severity).toBe('HIGH')

    await chmod(path, 0o600)
    const tight = (await run()).findings.find((f) => f.id === 'aws-static-keys')
    expect(tight?.severity).toBe('MEDIUM')
  })

  it('flags a world-readable SSH private key but not its .pub', async () => {
    await mkdir(join(home, '.ssh'))
    await writeFile(join(home, '.ssh', 'id_ed25519'), '-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n')
    await chmod(join(home, '.ssh', 'id_ed25519'), 0o644)
    await writeFile(join(home, '.ssh', 'id_ed25519.pub'), 'ssh-ed25519 AAAA...\n')
    const { findings } = await run()
    const sshFindings = findings.filter((f) => f.id === 'ssh-key-perms')
    expect(sshFindings).toHaveLength(1)
    expect(sshFindings[0]!.title).toContain('id_ed25519')
  })

  it('does not flag an SSH key with 0600 permissions', async () => {
    await mkdir(join(home, '.ssh'))
    const path = join(home, '.ssh', 'id_rsa')
    await writeFile(path, '-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n')
    await chmod(path, 0o600)
    expect(ids((await run()).findings)).not.toContain('ssh-key-perms')
  })

  it('flags a gh CLI oauth token', async () => {
    await mkdir(join(home, '.config', 'gh'), { recursive: true })
    await writeFile(join(home, '.config', 'gh', 'hosts.yml'), 'github.com:\n    oauth_token: gho_xxx\n    user: me\n')
    expect(ids((await run()).findings)).toContain('gh-cli-token')
  })

  it('flags a .env that .gitignore does not cover, in a git repo', async () => {
    await mkdir(join(target, '.git'))
    await writeFile(join(target, '.env'), 'API_KEY=xyz\n')
    await writeFile(join(target, '.gitignore'), 'node_modules\ndist\n')
    expect(ids((await run()).findings)).toContain('committable-env')
  })

  it('does not flag a .env covered by a .env* gitignore rule', async () => {
    await mkdir(join(target, '.git'))
    await writeFile(join(target, '.env'), 'API_KEY=xyz\n')
    await writeFile(join(target, '.gitignore'), 'node_modules\n.env*\n')
    expect(ids((await run()).findings)).not.toContain('committable-env')
  })

  it('ignores .env.example and does not flag outside a git repo', async () => {
    await writeFile(join(target, '.env.example'), 'API_KEY=\n')
    expect(ids((await run()).findings)).not.toContain('committable-env')

    // .env present but no .git directory -> nothing to accidentally commit
    await writeFile(join(target, '.env'), 'API_KEY=xyz\n')
    expect(ids((await run()).findings)).not.toContain('committable-env')
  })

  it('flags an exported secret in shell history', async () => {
    await writeFile(join(home, '.zsh_history'), 'ls -la\nexport AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCY\ncd ~\n')
    expect(ids((await run()).findings)).toContain('shell-history-secret')
  })

  it('does not flag benign shell history', async () => {
    await writeFile(join(home, '.bash_history'), 'ls\ncd project\nnpm test\nPORT=3000 npm start\n')
    expect(ids((await run()).findings)).not.toContain('shell-history-secret')
  })

  it('sorts findings by severity, highest first', async () => {
    await writeFile(join(home, '.npmrc'), '_authToken=npm_abc\n') // HIGH
    await mkdir(join(home, '.config', 'gh'), { recursive: true })
    await writeFile(join(home, '.config', 'gh', 'hosts.yml'), 'oauth_token: gho_x\n') // MEDIUM
    const { findings } = await run()
    const ranks = findings.map((f) => f.severity)
    const highIdx = ranks.indexOf('HIGH')
    const medIdx = ranks.indexOf('MEDIUM')
    expect(highIdx).toBeLessThan(medIdx)
  })
})
