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
  {
    name: 'AWS Access Key',
    severity: 'CRITICAL',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    mask: (match) => match.slice(0, 8) + '****' + match.slice(-4),
  },
  {
    name: 'AWS Secret Key',
    severity: 'CRITICAL',
    // 40-char base62 string following common assignment patterns
    pattern: /(?:aws[_\-]?secret[_\-]?(?:access[_\-]?)?key|AWS_SECRET)["\s=:]+([A-Za-z0-9\/+=]{40})/gi,
    mask: (match) => maskSecret(match),
  },
]
