import type { Severity } from '../patterns/types.js'
import type { AuditFinding, AuditResult } from '../audit/types.js'

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  gray: '\x1b[90m',
  green: '\x1b[32m',
}

const severityColor: Record<Severity, string> = {
  CRITICAL: colors.red,
  HIGH: colors.yellow,
  MEDIUM: colors.blue,
  LOW: colors.gray,
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function formatFinding(finding: AuditFinding): string {
  const color = severityColor[finding.severity]
  const label = `${color}${colors.bold}[${finding.severity}]${colors.reset}`
  const title = `${colors.bold}${finding.title}${colors.reset}`
  return [
    `  ${label} ${title}`,
    `  at ${colors.gray}${finding.location}${colors.reset}`,
    `  why ${colors.gray}${finding.detail}${colors.reset}`,
    `  fix ${colors.blue}${finding.remediation}${colors.reset}`,
    '',
  ].join('\n')
}

export function printAuditReport(result: AuditResult): void {
  if (result.findings.length === 0) {
    console.log(
      `${colors.green}No credential-hygiene issues found. Ran ${result.checked} checks in ${result.duration}ms.${colors.reset}`,
    )
    return
  }

  console.log(
    `\n${colors.bold}secretguard audit found ${result.findings.length} credential-hygiene issue(s)${colors.reset}\n`,
  )

  const groups = new Map<Severity, AuditFinding[]>()
  for (const severity of SEVERITY_ORDER) groups.set(severity, [])
  for (const finding of result.findings) groups.get(finding.severity)!.push(finding)

  for (const severity of SEVERITY_ORDER) {
    const group = groups.get(severity)!
    if (group.length === 0) continue
    const color = severityColor[severity]
    console.log(`${color}${colors.bold}── ${severity} (${group.length}) ──${colors.reset}\n`)
    for (const finding of group) console.log(formatFinding(finding))
  }

  console.log(`${colors.gray}Ran ${result.checked} checks in ${result.duration}ms${colors.reset}`)
}

export function printAuditJson(result: AuditResult): void {
  console.log(JSON.stringify(result, null, 2))
}
