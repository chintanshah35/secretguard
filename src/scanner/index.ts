import { stat } from 'fs/promises'
import { walkFiles } from './walker.js'
import { matchFile } from './matcher.js'
import { listGitFiles, isGitIgnored } from './git-files.js'
import { allPatterns } from '../patterns/index.js'
import { withoutRaw } from '../sanitize.js'
import type { ScanResult, ScanOptions } from '../patterns/types.js'

export async function scan(targetPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  const patterns = options.patterns ?? allPatterns
  const start = Date.now()
  let scanned = 0
  const findings = []

  const target = await stat(targetPath).catch(() => null)
  if (!target) throw new Error(`Path not found: ${targetPath}`)

  // An explicitly named target is opt-in, so honour it even when gitignored. For a file we
  // already bypass the gitignore filter; for a directory, `git ls-files` run inside an ignored
  // dir returns nothing, so detect that and walk it without the filter.
  let gitFiles = null
  if (!target.isFile() && options.gitignore !== false) {
    gitFiles = await listGitFiles(targetPath)
    if (gitFiles && gitFiles.size === 0 && (await isGitIgnored(targetPath))) {
      gitFiles = null
    }
  }

  const files = target.isFile()
    ? [targetPath]
    : walkFiles(targetPath, { root: targetPath, ignore: options.ignore, gitFiles })

  // Skip rules (e.g. `tests/`) match on the path relative to the scan root. For a single file
  // use the cwd so a path like `tests/fixture.ts` keeps its directory prefix, matching a dir scan.
  const skipRoot = target.isFile() ? process.cwd() : targetPath

  for await (const filePath of files) {
    const fileFindings = await matchFile(filePath, patterns, skipRoot)
    findings.push(...fileFindings)
    scanned++
  }

  return {
    scanned,
    findings: options.includeRaw ? findings : withoutRaw(findings),
    duration: Date.now() - start,
  }
}
