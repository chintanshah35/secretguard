import { readFile } from 'fs/promises'
import type { Finding, PatternMatch } from '../patterns/types.js'
import { BINARY_EXTENSIONS } from './ignore.js'
import { extname } from 'path'

export async function matchFile(
  filePath: string,
  patterns: PatternMatch[]
): Promise<Finding[]> {
  const extension = extname(filePath).toLowerCase()
  if (BINARY_EXTENSIONS.has(extension)) return []

  let content: string
  try {
    content = await readFile(filePath, 'utf-8')
  } catch {
    return []
  }

  // Skip files that appear binary by checking for null bytes in first 512 chars
  if (content.slice(0, 512).includes('\0')) return []
  const lines = content.split('\n')
  const findings: Finding[] = []

  for (const pattern of patterns) {
    // Reset stateful regex before each file
    pattern.pattern.lastIndex = 0

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex]!
      pattern.pattern.lastIndex = 0

      let match: RegExpExecArray | null
      while ((match = pattern.pattern.exec(line)) !== null) {
        if (pattern.filter && !pattern.filter(match[0])) continue
        findings.push({
          file: filePath,
          line: lineIndex + 1,
          column: match.index + 1,
          pattern: pattern.name,
          severity: pattern.severity,
          raw: match[0],
          masked: pattern.mask(match[0]),
        })
      }
    }
  }

  return findings
}
