import type { PatternMatch } from './types.js'

// PII patterns are suppressed in test/fixture/mock files where synthetic data is expected,
// in minified bundles and source maps, and in lockfiles, which list package maintainer emails.
// Credentials still run on all of these because private registry URLs can carry tokens.
const TEST_FILES = /(?:\.test\.|(?:^|[\\/])tests?[\\/]|\.min\.(?:js|css)$|\.map$|\.spec\.|__tests__[\\/]|__mocks__[\\/]|(?:^|[\\/])(?:fixtures|mocks|stubs)[\\/]|(?:^|[\\/])(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock|composer\.lock|Gemfile\.lock|poetry\.lock|Cargo\.lock)$)/

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

// Package specs like slash@3.0.0.js or vite@5.1.0 look like emails to the regex
const FILE_EXTENSIONS = /\.(?:m?js|cjs|jsx|tsx?|css|map|json|html?|md|svg|png|jpe?g|gif|webp|woff2?|ttf|gz|tgz|zip|wasm|node)$/

// In scheme://user:password@host the password@host part is a credential, not an email.
// The password can hold symbols (! # & $ <) that split the email match, so accept any
// run of password characters between the userinfo ':' and the match, not just up to ':'.
const isUrlUserinfo = (line: string, index: number) =>
  /:\/\/[^\s/@]+:[^\s@]*$/.test(line.slice(Math.max(0, index - 256), index))

const isRealEmail = (email: string, line = '', index = 0): boolean => {
  if (isUrlUserinfo(line, index)) return false
  const [local, domain] = email.toLowerCase().split('@')
  if (!local || !domain) return false
  if (FAKE_DOMAINS.has(domain)) return false
  if ([...FAKE_DOMAINS].some((fake) => domain.endsWith('.' + fake))) return false
  if (FAKE_LOCALS.has(local)) return false
  if (local === 'git') return false
  if (domain.split('.').some((label) => /^\d+$/.test(label))) return false
  return !FILE_EXTENSIONS.test(domain)
}

// Author emails in these files are published on purpose
const EMAIL_SKIP_FILES = new RegExp(
  TEST_FILES.source + '|(?:^|[\\\\/])(?:package\\.json|LICEN[CS]E|AUTHORS|CONTRIBUTORS|CODE_OF_CONDUCT|NOTICE|MAINTAINERS|CODEOWNERS)(?:\\.\\w+)?$',
  'i'
)

// OIDs and RFC section numbers (1.3.6.1, 2.4.1.3) are dotted quads of small numbers
const isLikelyPublicIp = (match: string, line = '', index = 0) => {
  // Docker/image tags like `postgres:15.8.1.100` read as IPs — skip a quad glued to `name:`
  if (/[A-Za-z][\w.\-]*:$/.test(line.slice(0, index))) return false
  const octets = match.split('.').map(Number)
  if (octets[0] === 0) return false
  if (octets[0] === 169 && octets[1] === 254) return false
  if (match === '255.255.255.255') return false
  return octets.some((octet) => octet >= 32)
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

// A minified bundle has "phone" somewhere on its one line, so the label has to sit next to the number
const hasLabelNear = (label: RegExp, line: string, index: number, match: string) =>
  label.test(line.slice(Math.max(0, index - 40), index + match.length + 40))

// NANP area codes and exchanges never start with 0 or 1, and the 555 exchange is fictional
const isValidNanp = (match: string) => {
  const digits = match.replace(/\D/g, '').slice(-10)
  return /^[2-9]\d{2}[2-9]/.test(digits) && digits.slice(3, 6) !== '555'
}

const PHONE_LABEL = /phone|\btel\b|mobile|\bcell\b|\bfax\b|contact|\bcall\b/i

// Unformatted 10-digit runs are usually unix timestamps, cache busters or z-index values
const isLikelyUsPhone = (match: string, line = '', index = 0): boolean =>
  isRealPhone(match) &&
  isValidNanp(match) &&
  (/[-.\s()+]/.test(match) || hasLabelNear(PHONE_LABEL, line, index, match))

const SSN_LABEL = /\bssn\b|social[\s_-]?security|\bss#/i

// Bare 9-digit numbers are everywhere (IDs, constants, timestamps), so only
// the dashed form counts on its own
const isLikelySsn = (match: string, line = '', index = 0): boolean =>
  /^\d{3}-\d{2}-\d{4}$/.test(match) || hasLabelNear(SSN_LABEL, line, index, match)

// Order numbers and snowflake IDs share card prefixes; real cards pass Luhn
const passesLuhn = (match: string): boolean => {
  const digits = match.replace(/\D/g, '')
  let sum = 0
  for (let index = 0; index < digits.length; index++) {
    let digit = Number(digits[digits.length - 1 - index])
    if (index % 2 === 1) {
      digit *= 2
      if (digit > 9) digit -= 9
    }
    sum += digit
  }
  return sum % 10 === 0
}

export const piiPatterns: PatternMatch[] = [
  {
    name: 'Email Address',
    severity: 'MEDIUM',
    // The lookbehind pins the start to the beginning of a run and the bounds follow RFC 5321.
    // Without them, long minified or base64 lines backtrack quadratically and hang the scan.
    pattern: /(?<![a-zA-Z0-9._%+\-])[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,24}\b/g,
    skipFiles: EMAIL_SKIP_FILES,
    filter: isRealEmail,
    mask: (match) => {
      const [local, domain] = match.split('@')
      return maskMiddle(local!) + '@' + domain
    },
  },
  {
    name: 'Phone Number (US)',
    severity: 'MEDIUM',
    // Lookbehind stops matches on the tail of longer numbers and identifiers (go2933276541)
    pattern: /(?<![\w.])(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    skipFiles: TEST_FILES,
    filter: isLikelyUsPhone,
    mask: (match) => {
      const digits = match.replace(/\D/g, '')
      return digits.slice(0, 3) + '-****-' + digits.slice(-2)
    },
  },
  {
    name: 'Phone Number (International)',
    severity: 'MEDIUM',
    pattern: /(?<!\d)\+(?:[1-9]\d{0,2})[-.\s]?\(?\d{1,4}\)?(?:[-.\s]\d{1,4}){2,4}\b/g,
    skipFiles: TEST_FILES,
    filter: isRealPhone,
    mask: (match) => match.slice(0, 4) + '****' + match.slice(-2),
  },
  {
    name: 'SSN',
    severity: 'CRITICAL',
    // Lookbehind stops matches inside decimals like 0.356563782
    pattern: /(?<![\d.])\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    skipFiles: TEST_FILES,
    filter: isLikelySsn,
    mask: (match) => '***-**-' + match.replace(/\D/g, '').slice(-4),
  },
  {
    name: 'Credit Card',
    severity: 'CRITICAL',
    // Visa, Mastercard, Amex, Discover
    pattern: /(?<![\d.])\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    skipFiles: TEST_FILES,
    filter: passesLuhn,
    mask: (match) => {
      const digits = match.replace(/\D/g, '')
      return '**** **** **** ' + digits.slice(-4)
    },
  },
  {
    name: 'IPv4 Address',
    severity: 'LOW',
    // Excludes obviously safe ranges: localhost (127.x), private (10.x, 192.168.x, 172.16-31.x)
    // Lookarounds skip version strings like Chrome/120.0.0.0, v1.2.3.4 and 1.2.3.4.5
    pattern: /(?<![\w/.-])(?<![Vv]ersion\s?)\b(?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b(?!\.\d)/g,
    skipFiles: TEST_FILES,
    filter: isLikelyPublicIp,
    mask: (match) => {
      const parts = match.split('.')
      return `${parts[0]}.${parts[1]}.***.***`
    },
  },
]
