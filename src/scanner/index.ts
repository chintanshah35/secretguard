import { walkFiles } from './walker.js'
import { matchFile } from './matcher.js'
import { allPatterns } from '../patterns/index.js'
import { withoutRaw } from '../sanitize.js'
import type { ScanResult, ScanOptions } from '../patterns/types.js'

export async function scan(targetPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  const patterns = options.patterns ?? allPatterns
  const start = Date.now()
  let scanned = 0
  const findings = []

  for await (const filePath of walkFiles(targetPath, { root: targetPath, ignore: options.ignore })) {
    const fileFindings = await matchFile(filePath, patterns)
    findings.push(...fileFindings)
    scanned++
  }

  return {
    scanned,
    findings: options.includeRaw ? findings : withoutRaw(findings),
    duration: Date.now() - start,
  }
}
