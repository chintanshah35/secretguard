import { readFile, writeFile } from 'fs/promises'
import type { Finding } from './patterns/types.js'

type BaselineEntry = {
  file: string
  pattern: string
  masked: string
}

type BaselineFile = {
  version: 1
  entries: BaselineEntry[]
}

function toKey(entry: BaselineEntry): string {
  return `${entry.file}::${entry.pattern}::${entry.masked}`
}

export async function loadBaseline(path: string): Promise<Set<string>> {
  try {
    const content = await readFile(path, 'utf-8')
    const data: BaselineFile = JSON.parse(content)
    return new Set(data.entries.map(toKey))
  } catch {
    return new Set()
  }
}

export function filterBaseline(findings: Finding[], baseline: Set<string>): Finding[] {
  return findings.filter((finding) => {
    const key = toKey({ file: finding.file, pattern: finding.pattern, masked: finding.masked })
    return !baseline.has(key)
  })
}

export async function writeBaseline(path: string, findings: Finding[]): Promise<void> {
  const entries: BaselineEntry[] = findings.map((finding) => ({
    file: finding.file,
    pattern: finding.pattern,
    masked: finding.masked,
  }))

  const data: BaselineFile = { version: 1, entries }
  await writeFile(path, JSON.stringify(data, null, 2) + '\n', 'utf-8')
}
