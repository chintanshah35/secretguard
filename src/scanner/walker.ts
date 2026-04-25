import { readdir, stat } from 'fs/promises'
import { join, relative } from 'path'

export type WalkerOptions = {
  ignore?: string[]
  root: string
}

const DEFAULT_IGNORE = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.nuxt']

export async function* walkFiles(directory: string, options: WalkerOptions): AsyncGenerator<string> {
  const ignore = [...DEFAULT_IGNORE, ...(options.ignore ?? [])]
  yield* walk(directory, ignore, options.root)
}

async function* walk(directory: string, ignore: string[], root: string): AsyncGenerator<string> {
  const entries = await readdir(directory, { withFileTypes: true })

  for (const entry of entries) {
    const fullPath = join(directory, entry.name)
    const relativePath = relative(root, fullPath)

    if (ignore.some((pattern) => relativePath.includes(pattern))) continue

    if (entry.isDirectory()) {
      yield* walk(fullPath, ignore, root)
    } else if (entry.isFile()) {
      yield fullPath
    }
  }
}
