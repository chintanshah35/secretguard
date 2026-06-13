import { execFile } from 'child_process'
import { promisify } from 'util'
import { allPatterns } from '../patterns/index.js'
import type { PatternMatch, Severity } from '../patterns/types.js'

const execFileAsync = promisify(execFile)

export type HistoryFinding = {
  commitHash: string
  commitShort: string
  commitAuthor: string
  commitDate: string
  commitMessage: string
  file: string
  line: number
  pattern: string
  severity: Severity
  masked: string
}

export type HistoryScanResult = {
  commitsScanned: number
  findings: HistoryFinding[]
  duration: number
}

type CommitMeta = {
  hash: string
  short: string
  author: string
  date: string
  message: string
}

function parseGitLog(raw: string): Array<{ meta: CommitMeta; diff: string }> {
  const chunks: Array<{ meta: CommitMeta; diff: string }> = []

  // Each commit block starts with the sentinel line we inject via --format
  const commitBlocks = raw.split(/^SECRETGUARD_COMMIT /m).filter(Boolean)

  for (const block of commitBlocks) {
    const newline = block.indexOf('\n')
    if (newline === -1) continue

    const headerLine = block.slice(0, newline)
    const diff = block.slice(newline + 1)

    // Format: hash|short|author|date|message
    const parts = headerLine.split('|')
    if (parts.length < 5) continue

    const [hash, short, author, date, ...msgParts] = parts
    chunks.push({
      meta: {
        hash: hash!.trim(),
        short: short!.trim(),
        author: author!.trim(),
        date: date!.trim(),
        message: msgParts.join('|').trim(),
      },
      diff,
    })
  }

  return chunks
}

function scanDiff(
  diff: string,
  meta: CommitMeta,
  patterns: PatternMatch[],
): HistoryFinding[] {
  const findings: HistoryFinding[] = []
  const lines = diff.split('\n')

  let currentFile = ''
  let lineNumber = 0

  for (const line of lines) {
    // Track which file the diff is for
    if (line.startsWith('+++ b/')) {
      currentFile = line.slice(6).trim()
      lineNumber = 0
      continue
    }
    if (line.startsWith('@@ ')) {
      // Parse hunk header to get starting line number: @@ -a,b +c,d @@
      const match = line.match(/@@ [^+]*\+(\d+)/)
      lineNumber = match ? parseInt(match[1]!, 10) - 1 : 0
      continue
    }
    if (line.startsWith('-') || line.startsWith('\\')) continue
    if (line.startsWith('+')) {
      lineNumber++
      const content = line.slice(1)

      for (const pattern of patterns) {
        pattern.pattern.lastIndex = 0
        let match: RegExpExecArray | null
        while ((match = pattern.pattern.exec(content)) !== null) {
          if (pattern.filter && !pattern.filter(match[0])) continue
          findings.push({
            commitHash: meta.hash,
            commitShort: meta.short,
            commitAuthor: meta.author,
            commitDate: meta.date,
            commitMessage: meta.message,
            file: currentFile,
            line: lineNumber,
            pattern: pattern.name,
            severity: pattern.severity,
            masked: pattern.mask(match[0]),
          })
        }
      }
    } else {
      lineNumber++
    }
  }

  return findings
}

export async function scanHistory(
  targetPath: string,
  options: { patterns?: PatternMatch[] } = {},
): Promise<HistoryScanResult> {
  const patterns = options.patterns ?? allPatterns
  const start = Date.now()

  let raw: string
  try {
    const result = await execFileAsync(
      'git',
      [
        'log',
        '--patch',
        '--diff-filter=A',  // only added lines
        '--no-merges',
        '--format=SECRETGUARD_COMMIT %H|%h|%an|%ai|%s',
        '--',
        '.',
      ],
      { cwd: targetPath, maxBuffer: 100 * 1024 * 1024 },
    )
    raw = result.stdout
  } catch {
    throw new Error(
      `Failed to run git log in '${targetPath}'. Make sure this is a git repository.`,
    )
  }

  const commits = parseGitLog(raw)
  const allFindings: HistoryFinding[] = []

  for (const { meta, diff } of commits) {
    allFindings.push(...scanDiff(diff, meta, patterns))
  }

  // Deduplicate: same pattern + masked value across commits only keeps first occurrence
  const seen = new Set<string>()
  const dedupedFindings = allFindings.filter((finding) => {
    const key = `${finding.file}:${finding.pattern}:${finding.masked}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })

  return {
    commitsScanned: commits.length,
    findings: dedupedFindings,
    duration: Date.now() - start,
  }
}
