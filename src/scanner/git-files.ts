import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

// Tracked plus untracked-but-not-ignored files, relative to `directory`.
// Null outside a git work tree (or without git), so the caller walks everything.
export async function listGitFiles(directory: string): Promise<Set<string> | null> {
  try {
    const { stdout } = await execFileAsync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], {
      cwd: directory,
      maxBuffer: 256 * 1024 * 1024,
    })
    return new Set(stdout.split('\0').filter(Boolean))
  } catch {
    return null
  }
}
