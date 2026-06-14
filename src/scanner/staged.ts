import { execFile } from 'child_process'
import { promisify } from 'util'
import { allPatterns } from '../patterns/index.js'
import type { PatternMatch, Severity, Finding, ScanResult } from '../patterns/types.js'

const execFileAsync = promisify(execFile)

async function getStagedDiff(cwd: string): Promise<string> {
  try {
    const result = await execFileAsync('git', ['diff', '--cached', '--unified=0'], { cwd })
    return result.stdout
  } catch {
    throw new Error(
      `Failed to get staged diff in '${cwd}'. Make sure this is a git repository with staged changes.`,
    )
  }
}

function scanStagedDiff(diff: string, patterns: PatternMatch[]): Finding[] {
  const findings: Finding[] = []
  const lines = diff.split('\n')

  let currentFile = ''
  let lineNumber = 0

  for (const line of lines) {
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6).trim()
      lineNumber = 0
      continue
    }
    if (line.startsWith('@@ ')) {
      const match = line.match(/@@ [^+]*\+(\d+)/)
      lineNumber = match ? parseInt(match[1]!, 10) - 1 : 0
      continue
    }
    if (line.startsWith('-') || line.startsWith('\\')) continue
    if (line.startsWith('+')) {
      lineNumber++
      const content = line.slice(1)
      let column = 1

      for (const pattern of patterns) {
        pattern.pattern.lastIndex = 0
        let match: RegExpExecArray | null
        while ((match = pattern.pattern.exec(content)) !== null) {
          if (pattern.filter && !pattern.filter(match[0])) continue
          if (pattern.skipFiles?.test(currentFile)) continue
          column = (match.index ?? 0) + 1
          findings.push({
            file: currentFile,
            line: lineNumber,
            column,
            pattern: pattern.name,
            severity: pattern.severity,
            masked: pattern.mask(match[0]),
            raw: match[0],
          })
        }
      }
    } else {
      lineNumber++
    }
  }

  return findings
}

export async function scanStaged(
  targetPath: string,
  options: { patterns?: PatternMatch[] } = {},
): Promise<ScanResult> {
  const patterns = options.patterns ?? allPatterns
  const start = Date.now()
  const diff = await getStagedDiff(targetPath)
  const findings = scanStagedDiff(diff, patterns)

  // Count unique files touched
  const files = new Set(findings.map((f) => f.file)).size

  return {
    scanned: files,
    findings,
    duration: Date.now() - start,
  }
}

export type StagedSeverity = Severity
