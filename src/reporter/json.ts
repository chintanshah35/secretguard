import type { ScanResult } from '../patterns/types.js'

export function printJson(result: ScanResult): void {
  const output = {
    summary: {
      scanned: result.scanned,
      findings: result.findings.length,
      duration: result.duration,
      critical: result.findings.filter((f) => f.severity === 'CRITICAL').length,
      high: result.findings.filter((f) => f.severity === 'HIGH').length,
      medium: result.findings.filter((f) => f.severity === 'MEDIUM').length,
      low: result.findings.filter((f) => f.severity === 'LOW').length,
    },
    findings: result.findings.map((finding) => ({
      file: finding.file,
      line: finding.line,
      column: finding.column,
      pattern: finding.pattern,
      severity: finding.severity,
      masked: finding.masked,
    })),
  }

  console.log(JSON.stringify(output, null, 2))
}
