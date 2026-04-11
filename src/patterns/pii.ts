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
  {
    name: 'SSN',
    severity: 'CRITICAL',
    // Matches 123-45-6789 and 123456789 but avoids phone number collisions
    pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    mask: (match) => '***-**-' + match.replace(/\D/g, '').slice(-4),
  },
  {
    name: 'Credit Card',
    severity: 'CRITICAL',
    // Visa, Mastercard, Amex, Discover
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    mask: (match) => {
      const digits = match.replace(/\D/g, '')
      return '**** **** **** ' + digits.slice(-4)
    },
  },
]
