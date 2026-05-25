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

export type Finding = {
  file: string
  line: number
  column: number
  pattern: string
  severity: Severity
  masked: string
  raw: string
}

export type ScanResult = {
  scanned: number
  findings: Finding[]
  duration: number
}

export type ScanOptions = {
  ignore?: string[]
  patterns?: PatternMatch[]
}
