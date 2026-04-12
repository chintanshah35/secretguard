import { piiPatterns } from './pii.js'
import { credentialPatterns } from './credentials.js'
import type { PatternMatch } from './types.js'

export const allPatterns: PatternMatch[] = [
  ...credentialPatterns,
  ...piiPatterns,
]

export { piiPatterns, credentialPatterns }
export type { PatternMatch, Finding, ScanResult, Severity } from './types.js'
