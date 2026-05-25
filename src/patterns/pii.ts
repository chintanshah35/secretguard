import type { PatternMatch } from './types.js'

// PII patterns are suppressed in test/fixture/mock files where synthetic data is expected
const TEST_FILES = /(?:\.test\.|\.spec\.|__tests__[\\/]|__mocks__[\\/]|[\\/]fixtures[\\/]|[\\/]mocks[\\/]|[\\/]stubs[\\/])/

const maskMiddle = (value: string): string => {
  if (value.length <= 6) return '*'.repeat(value.length)
  return value.slice(0, 3) + '*'.repeat(value.length - 6) + value.slice(-3)
}

// Domains that are reserved for documentation/testing — RFC 2606 + common fakes
const FAKE_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net', 'example.io', 'example.co',
  'test.com', 'test.org', 'test.net', 'test.io', 'test.local',
  'localhost', 'local', 'invalid', 'dummy.com', 'fake.com',
  'foo.com', 'bar.com', 'baz.com', 'foo.bar', 'acme.com',
  'email.com', 'mail.com', 'domain.com', 'company.com',
  'yourdomain.com', 'mydomain.com', 'placeholder.com',
])

// Local parts that are obviously synthetic
const FAKE_LOCALS = new Set([
  'test', 'user', 'admin', 'demo', 'sample', 'placeholder', 'example',
  'noreply', 'no-reply', 'noone', 'nobody', 'someone',
  'foo', 'bar', 'baz', 'qux', 'alice', 'bob',
  'john', 'jane', 'johndoe', 'janedoe', 'john.doe', 'jane.doe',
])

const isRealEmail = (email: string): boolean => {
  const [local, domain] = email.toLowerCase().split('@')
  if (!local || !domain) return false
  if (FAKE_DOMAINS.has(domain)) return false
  if (FAKE_LOCALS.has(local)) return false
  return true
}

const isRealPhone = (phone: string): boolean => {
  const digits = phone.replace(/\D/g, '')
  // Skip 555 area codes (US fictional standard)
  if (digits.startsWith('555') || digits.startsWith('1555')) return false
  // Skip all same digit (e.g. 1111111111, 5555555555)
  if (new Set(digits).size === 1) return false
  // Skip obvious test sequences
  if (digits.includes('1234567890') || digits.includes('0987654321')) return false
  // Skip all zeros or starts with 000
  if (digits.startsWith('000') || digits.startsWith('1000')) return false
  return true
}

export const piiPatterns: PatternMatch[] = [
  {
    name: 'Email Address',
    severity: 'MEDIUM',
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    skipFiles: TEST_FILES,
    filter: isRealEmail,
    mask: (match) => {
      const [local, domain] = match.split('@')
      return maskMiddle(local!) + '@' + domain
    },
  },
  {
    name: 'Phone Number (US)',
    severity: 'MEDIUM',
    pattern: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    skipFiles: TEST_FILES,
    filter: isRealPhone,
    mask: (match) => {
      const digits = match.replace(/\D/g, '')
      return digits.slice(0, 3) + '-****-' + digits.slice(-2)
    },
  },
  {
    name: 'Phone Number (International)',
    severity: 'MEDIUM',
    pattern: /\+(?:[1-9]\d{0,2})[-.\s]?\(?\d{1,4}\)?(?:[-.\s]\d{1,4}){2,4}\b/g,
    skipFiles: TEST_FILES,
    filter: isRealPhone,
    mask: (match) => match.slice(0, 4) + '****' + match.slice(-2),
  },
  {
    name: 'SSN',
    severity: 'CRITICAL',
    // Matches 123-45-6789 and 123456789 but avoids phone number collisions
    pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    skipFiles: TEST_FILES,
    mask: (match) => '***-**-' + match.replace(/\D/g, '').slice(-4),
  },
  {
    name: 'Credit Card',
    severity: 'CRITICAL',
    // Visa, Mastercard, Amex, Discover
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    skipFiles: TEST_FILES,
    mask: (match) => {
      const digits = match.replace(/\D/g, '')
      return '**** **** **** ' + digits.slice(-4)
    },
  },
  {
    name: 'IPv4 Address',
    severity: 'LOW',
    // Excludes obviously safe ranges: localhost (127.x), private (10.x, 192.168.x, 172.16-31.x)
    pattern: /\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    skipFiles: TEST_FILES,
    mask: (match) => {
      const parts = match.split('.')
      return `${parts[0]}.${parts[1]}.***.***`
    },
  },
]
