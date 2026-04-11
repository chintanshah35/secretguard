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
  {
    name: 'GitHub Personal Access Token',
    severity: 'CRITICAL',
    pattern: /\bghp_[a-zA-Z0-9]{36}\b/g,
    mask: (match) => match.slice(0, 8) + '****' + match.slice(-4),
  },
  {
    name: 'GitHub App Token',
    severity: 'CRITICAL',
    pattern: /\bghs_[a-zA-Z0-9]{36}\b/g,
    mask: (match) => match.slice(0, 8) + '****' + match.slice(-4),
  },
  {
    name: 'GitHub OAuth Token',
    severity: 'CRITICAL',
    pattern: /\bgho_[a-zA-Z0-9]{36}\b/g,
    mask: (match) => match.slice(0, 8) + '****' + match.slice(-4),
  },
  {
    name: 'Stripe Live Secret Key',
    severity: 'CRITICAL',
    pattern: /\bsk_live_[a-zA-Z0-9]{24,}\b/g,
    mask: (match) => match.slice(0, 12) + '****' + match.slice(-4),
  },
  {
    name: 'Stripe Live Publishable Key',
    severity: 'HIGH',
    pattern: /\bpk_live_[a-zA-Z0-9]{24,}\b/g,
    mask: (match) => match.slice(0, 12) + '****' + match.slice(-4),
  },
  {
    name: 'Generic API Key',
    severity: 'HIGH',
    // High-entropy 32+ char alphanumeric strings assigned to api_key/apiKey/API_KEY
    pattern: /(?:api[_\-]?key|apikey|API_KEY)["\s=:]+["']?([a-zA-Z0-9_\-]{32,})["']?/gi,
    mask: (match) => maskSecret(match),
  },
]
