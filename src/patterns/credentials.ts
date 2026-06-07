import type { PatternMatch } from './types.js'

const maskSecret = (match: string): string => {
  if (match.length === 0) return '****'
  if (match.length <= 4) return '*'.repeat(match.length)
  if (match.length <= 8) return match.slice(0, 2) + '*'.repeat(match.length - 2)
  return match.slice(0, 6) + '*'.repeat(Math.max(match.length - 10, 4)) + match.slice(-4)
}

export const credentialPatterns: PatternMatch[] = [
  {
    name: 'JWT Token',
    severity: 'HIGH',
    // Require all three parts and minimum realistic lengths to reduce false positives
    // on base64-encoded strings that happen to start with eyJ
    pattern: /eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}/g,
    mask: (match) => match.slice(0, 12) + '...[jwt]',
  },
  {
    name: 'OpenAI API Key',
    severity: 'CRITICAL',
    pattern: /\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b/g,
    mask: (match) => match.slice(0, 7) + '****' + match.slice(-4),
  },
  {
    name: 'Anthropic API Key',
    severity: 'CRITICAL',
    pattern: /\bsk-ant-[a-zA-Z0-9\-_]{93}\b/g,
    mask: (match) => match.slice(0, 10) + '****' + match.slice(-4),
  },
  {
    name: 'Slack Bot Token',
    severity: 'CRITICAL',
    pattern: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b/g,
    mask: (match) => match.slice(0, 10) + '****' + match.slice(-4),
  },
  {
    name: 'Slack User Token',
    severity: 'CRITICAL',
    pattern: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{32}\b/g,
    mask: (match) => match.slice(0, 10) + '****' + match.slice(-4),
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
    name: 'SendGrid API Key',
    severity: 'CRITICAL',
    pattern: /\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b/g,
    mask: (match) => match.slice(0, 6) + '****' + match.slice(-4),
  },
  {
    name: 'npm Access Token',
    severity: 'CRITICAL',
    pattern: /\bnpm_[a-zA-Z0-9]{36}\b/g,
    mask: (match) => match.slice(0, 8) + '****' + match.slice(-4),
  },
  {
    name: 'Google API Key',
    severity: 'HIGH',
    pattern: /\bAIzaSy[a-zA-Z0-9_\-]{33}\b/g,
    mask: (match) => match.slice(0, 10) + '****' + match.slice(-4),
  },
  {
    name: 'Generic API Key',
    severity: 'HIGH',
    // High-entropy 32+ char alphanumeric strings assigned to api_key/apiKey/API_KEY
    pattern: /(?:api[_\-]?key|apikey|API_KEY)["\s=:]+["']?([a-zA-Z0-9_\-]{32,})["']?/gi,
    mask: (match) => maskSecret(match),
  },
  {
    name: 'Database URL (PostgreSQL)',
    severity: 'CRITICAL',
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
    mask: (match) => {
      try {
        const url = new URL(match)
        return `${url.protocol}//****:****@${url.host}${url.pathname}`
      } catch {
        return 'postgres://****:****@[redacted]'
      }
    },
  },
  {
    name: 'Database URL (MySQL)',
    severity: 'CRITICAL',
    pattern: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/gi,
    mask: (match) => {
      try {
        const url = new URL(match)
        return `mysql://****:****@${url.host}${url.pathname}`
      } catch {
        return 'mysql://****:****@[redacted]'
      }
    },
  },
  {
    name: 'Database URL (MongoDB)',
    severity: 'CRITICAL',
    pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
    mask: (match) => match.replace(/:\/\/[^:]+:[^@]+@/, '://****:****@'),
  },
  {
    name: 'RSA Private Key',
    severity: 'CRITICAL',
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----/g,
    mask: () => '-----BEGIN RSA PRIVATE KEY----- [redacted] -----END RSA PRIVATE KEY-----',
  },
  {
    name: 'EC Private Key',
    severity: 'CRITICAL',
    pattern: /-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----/g,
    mask: () => '-----BEGIN EC PRIVATE KEY----- [redacted] -----END EC PRIVATE KEY-----',
  },
  {
    name: 'OpenSSH Private Key',
    severity: 'CRITICAL',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----/g,
    mask: () => '-----BEGIN OPENSSH PRIVATE KEY----- [redacted] -----END OPENSSH PRIVATE KEY-----',
  },
  {
    name: 'PGP Private Key',
    severity: 'CRITICAL',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----/g,
    mask: () => '-----BEGIN PGP PRIVATE KEY BLOCK----- [redacted] -----END PGP PRIVATE KEY BLOCK-----',
  },
  {
    name: 'GitLab Personal Access Token',
    severity: 'CRITICAL',
    pattern: /\bglpat-[a-zA-Z0-9_\-]{20}\b/g,
    mask: (match) => match.slice(0, 10) + '****' + match.slice(-4),
  },
  {
    name: 'GitHub Fine-Grained Token',
    severity: 'CRITICAL',
    pattern: /\bgithub_pat_[a-zA-Z0-9_]{82}\b/g,
    mask: (match) => match.slice(0, 14) + '****' + match.slice(-4),
  },
  {
    name: 'Twilio Account SID',
    severity: 'HIGH',
    // Twilio SIDs always start with AC and are 34 chars total
    pattern: /\bAC[a-f0-9]{32}\b/g,
    mask: (match) => match.slice(0, 8) + '****' + match.slice(-4),
  },
  {
    name: 'Twilio Auth Token',
    severity: 'CRITICAL',
    pattern: /(?:twilio[_\-]?auth[_\-]?token|TWILIO_AUTH_TOKEN)["\s=:]+["']?([a-f0-9]{32})["']?/gi,
    mask: (match) => maskSecret(match),
  },
  {
    name: 'HuggingFace Access Token',
    severity: 'CRITICAL',
    pattern: /\bhf_[a-zA-Z0-9]{34,}\b/g,
    mask: (match) => match.slice(0, 6) + '****' + match.slice(-4),
  },
  {
    name: 'Vercel Access Token',
    severity: 'CRITICAL',
    // Vercel personal tokens are 24-char base62 strings assigned to VERCEL_TOKEN etc.
    pattern: /(?:vercel[_\-]?(?:api[_\-]?)?token|VERCEL_TOKEN)["\s=:]+["']?([a-zA-Z0-9]{24,})["']?/gi,
    mask: (match) => maskSecret(match),
  },
  {
    name: 'Supabase Service Role Key',
    severity: 'CRITICAL',
    // Supabase service_role JWTs have a fixed header and are >200 chars
    pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]{60,}\.[a-zA-Z0-9_\-]{43}/g,
    mask: (match) => match.slice(0, 20) + '...[supabase-jwt]',
  },
  {
    name: 'Cloudflare API Token',
    severity: 'CRITICAL',
    pattern: /(?:cloudflare[_\-]?(?:api[_\-]?)?token|CF_API_TOKEN)["\s=:]+["']?([a-zA-Z0-9_\-]{40})["']?/gi,
    mask: (match) => maskSecret(match),
  },
  {
    name: 'Cloudflare Global API Key',
    severity: 'CRITICAL',
    pattern: /(?:cloudflare[_\-]?(?:global[_\-]?)?(?:api[_\-]?)?key|CF_API_KEY)["\s=:]+["']?([a-f0-9]{37})["']?/gi,
    mask: (match) => maskSecret(match),
  },
]
