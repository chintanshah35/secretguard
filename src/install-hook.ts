import { mkdir, writeFile, chmod } from 'fs/promises'
import { existsSync } from 'fs'
import { join } from 'path'

const HOOK_SCRIPT = `#!/bin/sh
# Installed by secretguard — remove this file to disable
npx secretguard --staged .
exit_code=$?
if [ $exit_code -ne 0 ]; then
  echo ""
  echo "secretguard: blocked commit due to CRITICAL findings."
  echo "Run 'secretguard .' to see full report, or use git commit --no-verify to bypass."
  echo ""
fi
exit $exit_code
`

export async function installHook(targetPath: string): Promise<void> {
  const hooksDir = join(targetPath, '.git', 'hooks')

  if (!existsSync(join(targetPath, '.git'))) {
    throw new Error(`No .git directory found in '${targetPath}'. Not a git repository.`)
  }

  await mkdir(hooksDir, { recursive: true })

  const hookPath = join(hooksDir, 'pre-commit')
  await writeFile(hookPath, HOOK_SCRIPT, 'utf-8')
  await chmod(hookPath, 0o755)
}
