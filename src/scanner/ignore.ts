export const DEFAULT_IGNORE = [
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  '.nuxt',
  '.turbo',
  '.cache',
  'vendor',
  '__pycache__',
  '.venv',
  '.yarn/releases',
  '.yarn/cache',
  '.pnp.cjs',
  '.pnp.loader.mjs',
]

const globToSource = (glob: string) =>
  glob.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')

// `tests` skips any path segment named tests (not `contest`), `src/mocks` skips that
// subtree, and `*` matches within one segment, so `*.min.js` works
export function isIgnored(relativePath: string, patterns: string[]): boolean {
  const path = relativePath.replace(/\\/g, '/')
  const segments = path.split('/')

  return patterns.some((raw) => {
    const pattern = raw.trim().replace(/\\/g, '/').replace(/^\.?\/+/, '').replace(/\/+$/, '')
    if (!pattern) return false
    if (pattern.includes('/')) return new RegExp(`^${globToSource(pattern)}(?:/|$)`).test(path)
    const segment = new RegExp(`^${globToSource(pattern)}$`)
    return segments.some((part) => segment.test(part))
  })
}

export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg',
  '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.dll', '.so', '.dylib',
  '.woff', '.woff2', '.ttf', '.eot',
  '.mp4', '.mp3', '.wav', '.avi',
  '.db', '.sqlite', '.sqlite3',
  '.lockb',
])
