import { readFile, readdir, stat } from 'fs/promises'
import { join } from 'path'
import type { AuditContext, AuditFinding, AuditRule } from './types.js'

// --- small fs helpers (no throwing: a missing file is simply "not present") ---

async function tryStat(path: string) {
  try {
    return await stat(path)
  } catch {
    return null
  }
}

async function readText(path: string): Promise<string | null> {
  try {
    return await readFile(path, 'utf-8')
  } catch {
    return null
  }
}

async function listDir(path: string): Promise<string[]> {
  try {
    return await readdir(path)
  } catch {
    return []
  }
}

/** Replace the home prefix with ~ so reports never print the real username path. */
function tilde(path: string, home: string): string {
  return path.startsWith(home) ? path.replace(home, '~') : path
}

/** True when group or other have any permission bit set (perms looser than 0600/0700). */
function groupOrWorldAccessible(mode: number): boolean {
  return (mode & 0o077) !== 0
}

function octal(mode: number): string {
  return '0' + (mode & 0o777).toString(8)
}

// --- rules -------------------------------------------------------------------

/**
 * The Black October signature: a stolen ~/.npmrc publish token is exactly how
 * LiteLLM, the OVHcloud CLI and others shipped poisoned releases.
 */
const npmPublishToken: AuditRule = async ({ home }) => {
  const path = join(home, '.npmrc')
  const text = await readText(path)
  if (!text || !/(^|\n)\s*[^#\n]*_authToken\s*=/.test(text)) return []
  const granular = /_authToken\s*=\s*npm_/.test(text)
  return [
    {
      id: 'npm-token-on-disk',
      title: 'npm auth token stored in ~/.npmrc',
      severity: 'HIGH',
      location: tilde(path, home),
      detail:
        'A long-lived npm token sits in plaintext on disk. A stolen ~/.npmrc token is the exact vector behind several Black October supply-chain poisonings (LiteLLM, OVHcloud CLI).' +
        (granular ? '' : ' This looks like a legacy (classic) token, which cannot be scoped read-only or to a single package.'),
      remediation:
        'Prefer trusted publishing (OIDC) for CI so no token lives on disk. For local use, create a short-lived, least-privilege token and rotate often: `npm token revoke <id>` then `npm token create`.',
    },
  ]
}

/** Long-lived AWS access keys on disk — the kind that, like Zeabur's, never expire. */
const awsLongLivedKeys: AuditRule = async ({ home, platform }) => {
  const path = join(home, '.aws', 'credentials')
  const info = await tryStat(path)
  if (!info) return []
  const text = (await readText(path)) ?? ''
  if (!/aws_secret_access_key\s*=/.test(text)) return []
  const loosePerms = platform !== 'win32' && groupOrWorldAccessible(info.mode)
  return [
    {
      id: 'aws-static-keys',
      title: 'Static AWS access keys in ~/.aws/credentials',
      severity: loosePerms ? 'HIGH' : 'MEDIUM',
      location: tilde(path, home),
      detail:
        'Static AWS keys do not expire on their own. Never-expiring admin credentials are what let the Zeabur breach run unnoticed.' +
        (loosePerms ? ` The file is readable beyond your user (mode ${octal(info.mode)}).` : ''),
      remediation:
        'Switch to short-lived credentials via AWS IAM Identity Center (`aws sso login`). If you must keep static keys, `chmod 600 ~/.aws/credentials` and rotate them on a schedule.',
    },
  ]
}

/** SSH private keys that other users on the machine can read. */
const sshKeyPerms: AuditRule = async ({ home, platform }) => {
  if (platform === 'win32') return []
  const dir = join(home, '.ssh')
  const names = await listDir(dir)
  const findings: AuditFinding[] = []
  for (const name of names) {
    if (name.endsWith('.pub') || name === 'known_hosts' || name === 'config' || name === 'authorized_keys') continue
    const path = join(dir, name)
    const info = await tryStat(path)
    if (!info || !info.isFile()) continue
    const head = (await readText(path)) ?? ''
    if (!/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(head)) continue
    if (groupOrWorldAccessible(info.mode)) {
      findings.push({
        id: 'ssh-key-perms',
        title: `SSH private key readable by others (${name})`,
        severity: 'HIGH',
        location: tilde(path, home),
        detail: `The private key is mode ${octal(info.mode)}; any other account on this machine can read it. ssh will also refuse to use it.`,
        remediation: `chmod 600 ${tilde(path, home)}`,
      })
    }
  }
  return findings
}

/** GitHub CLI OAuth token on disk. */
const ghCliToken: AuditRule = async ({ home }) => {
  const path = join(home, '.config', 'gh', 'hosts.yml')
  const text = await readText(path)
  if (!text || !/oauth_token:/.test(text)) return []
  return [
    {
      id: 'gh-cli-token',
      title: 'GitHub CLI OAuth token stored on disk',
      severity: 'MEDIUM',
      location: tilde(path, home),
      detail:
        'The `gh` token grants your full GitHub access, including pushing releases. A hijacked maintainer GitHub account is how the OVHcloud CLI release binaries were swapped.',
      remediation:
        'Keep the token short-lived and re-auth with `gh auth login` periodically; ensure 2FA and signed commits are on. Revoke under GitHub → Settings → Applications if a machine is lost.',
    },
  ]
}

/** .env files that are not covered by .gitignore — one `git add .` from a leak. */
const committableEnv: AuditRule = async ({ target }) => {
  const names = await listDir(target)
  const envFiles = names
    .filter((name) => name === '.env' || /^\.env\.[A-Za-z0-9_.-]+$/.test(name))
    .filter((name) => !name.endsWith('.example') && !name.endsWith('.sample'))
  if (envFiles.length === 0) return []
  // Only meaningful inside a git repo; outside one there is nothing to accidentally commit.
  if (!(await tryStat(join(target, '.git')))) return []
  const ignoreLines = ((await readText(join(target, '.gitignore'))) ?? '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
  const wildcards = new Set(['.env*', '*.env', '.env.*', '.env', '**/.env'])
  const covered = (name: string) => ignoreLines.some((line) => line === name || wildcards.has(line))
  const exposed = envFiles.filter((name) => !covered(name))
  if (exposed.length === 0) return []
  return [
    {
      id: 'committable-env',
      title: `Environment file not covered by .gitignore (${exposed.join(', ')})`,
      severity: 'HIGH',
      location: exposed.map((name) => join(target, name)).join(', '),
      detail:
        'A secret-bearing .env file that .gitignore does not cover is one `git add .` away from being committed and pushed.',
      remediation: `Add the file(s) to .gitignore (e.g. a line \`.env*\`), and run \`secretguard . --history\` to confirm nothing was committed already.`,
    },
  ]
}

/** Secrets exported in shell history — a common, overlooked leak. */
const shellHistoryLeaks: AuditRule = async ({ home }) => {
  const files = [join(home, '.zsh_history'), join(home, '.bash_history')]
  const findings: AuditFinding[] = []
  // Match `NAME=value` or `export NAME=value` where NAME looks secret-ish and value is substantial.
  const secretAssign = /\b(?:export\s+)?([A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\s*=\s*(['"]?)([^\s'"]{8,})\2/
  for (const path of files) {
    const text = await readText(path)
    if (!text) continue
    for (const line of text.split(/\r?\n/)) {
      const match = secretAssign.exec(line)
      if (!match) continue
      const variableName = match[1]!
      findings.push({
        id: 'shell-history-secret',
        title: `Secret assigned in shell history (${variableName})`,
        severity: 'MEDIUM',
        location: tilde(path, home),
        detail: `A value for ${variableName} is stored in your shell history in plaintext. Anything that reads your history file can harvest it.`,
        remediation: `Remove the line and rotate that credential. Prefix sensitive commands with a space to skip history, or use a secrets manager instead of inline env assignments.`,
      })
      break // one finding per history file is enough to prompt action
    }
  }
  return findings
}

export const auditRules: AuditRule[] = [
  npmPublishToken,
  awsLongLivedKeys,
  sshKeyPerms,
  ghCliToken,
  committableEnv,
  shellHistoryLeaks,
]
