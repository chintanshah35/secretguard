import type { Finding } from './patterns/types.js'
import { getRemediation } from './remediation.js'

export function withRemediation(findings: Finding[]): Finding[] {
  return findings.map((finding) => {
    const remediation = getRemediation(finding.pattern)
    if (!remediation) return finding
    return { ...finding, remediation }
  })
}
