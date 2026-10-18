import { execFile } from 'child_process'
import { promisify } from 'util'
import { dirname, basename } from 'path'

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

// True when `targetPath` is itself ignored by git (so `git ls-files` run inside it is empty).
// `git check-ignore -q` exits 0 when ignored, 1 when not ignored or not in a repo.
export async function isGitIgnored(targetPath: string): Promise<boolean> {
  try {
    // Run from the target's parent so check-ignore resolves in the right repo.
    await execFileAsync('git', ['check-ignore', '-q', '--', basename(targetPath)], {
      cwd: dirname(targetPath) || '.',
    })
    return true
  } catch {
    return false
  }
}
