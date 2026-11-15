import { homedir } from 'os'
import { auditRules } from './rules.js'
import type { AuditContext, AuditFinding, AuditResult } from './types.js'
import type { Severity } from '../patterns/types.js'

const SEVERITY_RANK: Record<Severity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }

export type RunAuditOptions = {
  target?: string
  /** Overridable for tests so we never read the real home directory. */
  home?: string
  platform?: NodeJS.Platform
}

/**
 * Audit the machine and project for exposed, long-lived credentials — the
 * "what could a thief grab right now, and which of these should have been
 * short-lived" question that Black October answered the hard way.
 *
 * Fully offline: no network, no values ever leave the machine.
 */
export async function runAudit(options: RunAuditOptions = {}): Promise<AuditResult> {
  const started = Date.now()
  const ctx: AuditContext = {
    home: options.home ?? homedir(),
    target: options.target ?? '.',
    platform: options.platform ?? process.platform,
  }

  const settled = await Promise.all(
    auditRules.map(async (rule) => {
      try {
        return await rule(ctx)
      } catch {
        // A rule that trips on an unreadable file must not sink the whole audit.
        return [] as AuditFinding[]
      }
    }),
  )

  const findings = settled.flat().sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])

  return { findings, checked: auditRules.length, duration: Date.now() - started }
}

export type { AuditFinding, AuditResult } from './types.js'
