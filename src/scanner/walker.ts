import { readdir } from 'fs/promises'
import { join, relative } from 'path'
import { DEFAULT_IGNORE, isIgnored } from './ignore.js'

export type WalkerOptions = {
  ignore?: string[]
  root: string
  /** When set, only these paths (relative to root, `/`-separated) are yielded */
  gitFiles?: Set<string> | null
}

type WalkState = {
  ignore: string[]
  root: string
  gitFiles: Set<string> | null
  gitDirectories: Set<string> | null
}

export async function* walkFiles(directory: string, options: WalkerOptions): AsyncGenerator<string> {
  const gitFiles = options.gitFiles ?? null
  yield* walk(directory, {
    ignore: [...DEFAULT_IGNORE, ...(options.ignore ?? [])],
    root: options.root,
    gitFiles,
    gitDirectories: gitFiles ? parentDirectories(gitFiles) : null,
  })
}

function parentDirectories(files: Set<string>): Set<string> {
  const directories = new Set<string>()
  for (const file of files) {
    const parts = file.split('/')
    for (let index = 1; index < parts.length; index++) {
      directories.add(parts.slice(0, index).join('/'))
    }
  }
  return directories
}

async function* walk(directory: string, state: WalkState): AsyncGenerator<string> {
  const entries = await readdir(directory, { withFileTypes: true })

  for (const entry of entries) {
    const fullPath = join(directory, entry.name)
    const relativePath = relative(state.root, fullPath)
    const gitPath = relativePath.replace(/\\/g, '/')

    if (isIgnored(relativePath, state.ignore)) continue

    if (entry.isDirectory()) {
      if (state.gitDirectories && !state.gitDirectories.has(gitPath)) continue
      yield* walk(fullPath, state)
    } else if (entry.isFile()) {
      if (state.gitFiles && !state.gitFiles.has(gitPath)) continue
      yield fullPath
    }
  }
}
