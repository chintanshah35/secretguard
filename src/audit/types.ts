import type { Severity } from '../patterns/types.js'

export type AuditFinding = {
  /** Stable rule id, e.g. "npm-token-on-disk". */
  id: string
  title: string
  severity: Severity
  /** Where the problem is — a file path, usually masked for the home dir. */
  location: string
  /** Why this matters, in one or two sentences. */
  detail: string
  /** What to do about it. */
  remediation: string
}

export type AuditResult = {
  findings: AuditFinding[]
  /** How many checks ran (not how many files were touched). */
  checked: number
  duration: number
}

export type AuditContext = {
  /** Home directory to inspect. Injectable so tests don't touch the real home. */
  home: string
  /** Project directory to inspect for committable secrets. */
  target: string
  /** Platform string; perms checks are skipped on win32. */
  platform: NodeJS.Platform
}

export type AuditRule = (ctx: AuditContext) => Promise<AuditFinding[]>
