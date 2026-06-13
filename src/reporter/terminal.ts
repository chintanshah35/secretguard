import type { ScanResult, Finding, Severity } from '../patterns/types.js'
import type { HistoryScanResult, HistoryFinding } from '../scanner/history.js'

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

function formatFinding(finding: Finding): string {
  const color = severityColor[finding.severity]
  const location = `${colors.gray}${finding.file}:${finding.line}:${finding.column}${colors.reset}`
  const label = `${color}${colors.bold}[${finding.severity}]${colors.reset}`
  const name = `${colors.bold}${finding.pattern}${colors.reset}`
  // Always show masked value — never expose raw secrets in terminal output
  const value = `${colors.gray}${finding.masked}${colors.reset}`

  return [
    `  ${label} ${name}`,
    `  at ${location}`,
    `  value ${value}`,
    '',
  ].join('\n')
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function groupBySeverity(findings: Finding[]): Map<Severity, Finding[]> {
  const groups = new Map<Severity, Finding[]>()
  for (const severity of SEVERITY_ORDER) groups.set(severity, [])
  for (const finding of findings) groups.get(finding.severity)!.push(finding)
  return groups
}

export function printReport(result: ScanResult): void {
  if (result.findings.length === 0) {
    console.log(`${colors.green}No findings. Scanned ${result.scanned} files in ${result.duration}ms.${colors.reset}`)
    return
  }

  console.log(`\n${colors.bold}secretguard found ${result.findings.length} issue(s) in ${result.scanned} files${colors.reset}\n`)

  const groups = groupBySeverity(result.findings)

  for (const severity of SEVERITY_ORDER) {
    const group = groups.get(severity)!
    if (group.length === 0) continue

    const color = severityColor[severity]
    console.log(`${color}${colors.bold}── ${severity} (${group.length}) ──${colors.reset}\n`)

    for (const finding of group) {
      console.log(formatFinding(finding))
    }
  }

  console.log(`${colors.gray}Completed in ${result.duration}ms${colors.reset}`)
}

function formatHistoryFinding(finding: HistoryFinding): string {
  const color = severityColor[finding.severity]
  const location = `${colors.gray}${finding.file}:${finding.line}${colors.reset}`
  const label = `${color}${colors.bold}[${finding.severity}]${colors.reset}`
  const name = `${colors.bold}${finding.pattern}${colors.reset}`
  const value = `${colors.gray}${finding.masked}${colors.reset}`
  const commit = `${colors.gray}${finding.commitShort} ${finding.commitDate.slice(0, 10)} — ${finding.commitMessage}${colors.reset}`
  const author = `${colors.gray}by ${finding.commitAuthor}${colors.reset}`

  return [
    `  ${label} ${name}`,
    `  at ${location}`,
    `  commit ${commit}`,
    `  ${author}`,
    `  value ${value}`,
    '',
  ].join('\n')
}

export function printHistoryReport(result: HistoryScanResult): void {
  if (result.findings.length === 0) {
    console.log(
      `${colors.green}No findings across ${result.commitsScanned} commits in ${result.duration}ms.${colors.reset}`,
    )
    return
  }

  console.log(
    `\n${colors.bold}secretguard found ${result.findings.length} issue(s) across ${result.commitsScanned} commits${colors.reset}\n`,
  )

  const groups = new Map<Severity, HistoryFinding[]>()
  for (const severity of SEVERITY_ORDER) groups.set(severity, [])
  for (const finding of result.findings) groups.get(finding.severity)!.push(finding)

  for (const severity of SEVERITY_ORDER) {
    const group = groups.get(severity)!
    if (group.length === 0) continue

    const color = severityColor[severity]
    console.log(`${color}${colors.bold}── ${severity} (${group.length}) ──${colors.reset}\n`)

    for (const finding of group) {
      console.log(formatHistoryFinding(finding))
    }
  }

  console.log(`${colors.gray}Completed in ${result.duration}ms${colors.reset}`)
}
