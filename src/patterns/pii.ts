import type { PatternMatch } from './types.js'

const maskMiddle = (value: string): string => {
  if (value.length <= 6) return '*'.repeat(value.length)
  return value.slice(0, 3) + '*'.repeat(value.length - 6) + value.slice(-3)
}

export const piiPatterns: PatternMatch[] = [
  {
    name: 'Email Address',
    severity: 'MEDIUM',
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    mask: (match) => {
      const [local, domain] = match.split('@')
      return maskMiddle(local!) + '@' + domain
    },
  },
  {
    name: 'Phone Number (US)',
    severity: 'MEDIUM',
    // Covers +1 (555) 123-4567, 555.123.4567, 5551234567, etc.
    pattern: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    mask: (match) => {
      const digits = match.replace(/\D/g, '')
      return digits.slice(0, 3) + '-****-' + digits.slice(-2)
    },
  },
  {
    name: 'Phone Number (International)',
    severity: 'MEDIUM',
    pattern: /\+(?:[1-9]\d{0,2})[-.\s]?\(?\d{1,4}\)?(?:[-.\s]\d{1,4}){2,4}\b/g,
    mask: (match) => match.slice(0, 4) + '****' + match.slice(-2),
  },
]
