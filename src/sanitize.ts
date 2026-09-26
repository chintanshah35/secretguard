import type { Finding } from './patterns/types.js'

/** Strip raw secret values from findings for safe public API / log output. */
export function withoutRaw(findings: Finding[]): Finding[] {
  return findings.map((finding) => {
    const { raw: _raw, ...safe } = finding
    return safe
  })
}
