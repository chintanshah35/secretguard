import { readFile } from 'fs/promises'
import { join } from 'path'

const IGNORE_FILENAME = '.secretguardignore'

/**
 * Loads patterns from .secretguardignore in the target directory.
 * Lines starting with # are comments. Blank lines are skipped.
 * Returns an empty array if the file does not exist.
 */
export async function loadIgnoreFile(targetPath: string): Promise<string[]> {
  const filePath = join(targetPath, IGNORE_FILENAME)
  try {
    const content = await readFile(filePath, 'utf-8')
    return content
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'))
  } catch {
    return []
  }
}
