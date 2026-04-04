import type { PatternMatch } from './types.js'

const maskMiddle = (value: string): string => {
  if (value.length <= 6) return '*'.repeat(value.length)
  return value.slice(0, 3) + '*'.repeat(value.length - 6) + value.slice(-3)
}

// TODO: add SSN, credit card, passport
export const piiPatterns: PatternMatch[] = [
  {
    name: 'Email Address',
    severity: 'MEDIUM',
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    mask: (match) => {
      const [local, domain] = match.split('@')
      return maskMiddle(local) + '@' + domain
    },
  },
  {
    name: 'Phone Number',
    severity: 'MEDIUM',
    pattern: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
    mask: (match) => match.slice(0, 3) + '****' + match.slice(-2),
  },
]
