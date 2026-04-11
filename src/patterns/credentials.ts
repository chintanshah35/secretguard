import type { PatternMatch } from './types.js'

const maskSecret = (match: string): string => {
  if (match.length <= 8) return match.slice(0, 4) + '****'
  return match.slice(0, 6) + '*'.repeat(match.length - 10) + match.slice(-4)
}

export const credentialPatterns: PatternMatch[] = [
  {
    name: 'JWT Token',
    severity: 'HIGH',
    pattern: /eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/g,
    mask: (match) => match.slice(0, 12) + '...[jwt]',
  },
]
