export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type PatternMatch = {
  name: string
  severity: Severity
  pattern: RegExp
  mask: (match: string) => string
  /** Return false to skip this match — use to reduce false positives */
  filter?: (match: string) => boolean
  /** Skip this pattern entirely for files whose path matches — e.g. test files */
  skipFiles?: RegExp
}

export type VerificationStatus = 'confirmed' | 'invalid' | 'error' | 'unsupported' | 'skipped'

export type Verification = {
  status: VerificationStatus
  detail: string
}

export type FindingRemediation = {
  revokeUrl: string
  steps: string[]
}

export type Finding = {
  file: string
  line: number
  column: number
  pattern: string
  severity: Severity
  masked: string
  /** Present only when scan/includeRaw is enabled. Prefer masked in logs. */
  raw?: string
  remediation?: FindingRemediation
  verification?: Verification
}

export type ScanResult = {
  scanned: number
  findings: Finding[]
  duration: number
}

export type ScanOptions = {
  ignore?: string[]
  patterns?: PatternMatch[]
  /** Include raw secret values on findings. Default false to avoid accidental leaks. */
  includeRaw?: boolean
}
