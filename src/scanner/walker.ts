import { readdir } from 'fs/promises'
import { join } from 'path'

// TODO: add ignore support, binary detection
export async function* walkFiles(directory: string): AsyncGenerator<string> {
  const entries = await readdir(directory, { withFileTypes: true })

  for (const entry of entries) {
    const fullPath = join(directory, entry.name)
    if (entry.isDirectory()) {
      yield* walkFiles(fullPath)
    } else if (entry.isFile()) {
      yield fullPath
    }
  }
}
