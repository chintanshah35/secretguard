import { describe, it, expect } from 'vitest'
import { writeFile, unlink } from 'fs/promises'
import { readFileSync } from 'fs'
import { join, dirname } from 'path'
import { tmpdir } from 'os'
import { fileURLToPath } from 'url'
import { piiPatterns } from '../src/patterns/pii.js'
import { credentialPatterns } from '../src/patterns/credentials.js'
import { loadIgnoreFile } from '../src/scanner/ignorefile.js'

function findPattern(patterns: typeof piiPatterns, name: string) {
  const pattern = patterns.find((p) => p.name === name)
  if (!pattern) throw new Error(`Pattern not found: ${name}`)
  return pattern
}

function matches(pattern: RegExp, input: string): string[] {
  pattern.lastIndex = 0
  const results: string[] = []
  let match: RegExpExecArray | null
  while ((match = pattern.exec(input)) !== null) {
    results.push(match[0])
  }
  return results
}

describe('PII patterns', () => {
  it('detects real email addresses', () => {
    const entry = findPattern(piiPatterns, 'Email Address')
    const real = matches(entry.pattern, 'contact chintan@gmail.com today')
    expect(real.filter((m) => entry.filter!(m))).toHaveLength(1)
  })

  it('filters fake email domains', () => {
    const entry = findPattern(piiPatterns, 'Email Address')
    const fakes = ['user@example.com', 'test@test.com', 'admin@localhost', 'foo@foo.com']
    for (const email of fakes) {
      expect(entry.filter!(email)).toBe(false)
    }
  })

  it('detects real US phone numbers', () => {
    const entry = findPattern(piiPatterns, 'Phone Number (US)')
    expect(entry.filter!('415-823-9147')).toBe(true)
  })

  it('filters fake US phone numbers', () => {
    const entry = findPattern(piiPatterns, 'Phone Number (US)')
    expect(entry.filter!('555-123-4567')).toBe(false)
    expect(entry.filter!('1234567890')).toBe(false)
    expect(entry.filter!('1111111111')).toBe(false)
  })

  it('skips PII patterns in test and fixture files', () => {
    const entry = findPattern(piiPatterns, 'Email Address')
    expect(entry.skipFiles!.test('/src/auth.test.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/__tests__/auth.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/fixtures/users.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/mocks/data.ts')).toBe(true)
    expect(entry.skipFiles!.test('/src/auth.ts')).toBe(false)
    expect(entry.skipFiles!.test('/src/controllers/user.ts')).toBe(false)
  })

  it('detects SSNs', () => {
    const { pattern } = findPattern(piiPatterns, 'SSN')
    expect(matches(pattern, 'ssn: 123-45-6789')).toHaveLength(1)
    expect(matches(pattern, 'ssn: 000-45-6789')).toHaveLength(0)
  })

  it('detects credit cards', () => {
    const { pattern } = findPattern(piiPatterns, 'Credit Card')
    expect(matches(pattern, '4111 1111 1111 1111')).toHaveLength(1)
    expect(matches(pattern, '5500-0000-0000-0004')).toHaveLength(1)
  })
})

describe('Credential patterns', () => {
  it('detects AWS access keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'AWS Access Key')
    expect(matches(pattern, 'AKIAIOSFODNN7EXAMPLE')).toHaveLength(1)
    expect(matches(pattern, 'not-an-aws-key')).toHaveLength(0)
  })

  it('detects GitHub tokens', () => {
    const ghp = findPattern(credentialPatterns, 'GitHub Personal Access Token')
    // ghp_ + exactly 36 alphanumeric chars
    expect(matches(ghp.pattern, 'ghp_abcdefghijklmnopqrstuvwxyz1234567890')).toHaveLength(1)
    expect(matches(ghp.pattern, 'ghp_tooshort')).toHaveLength(0)
  })

  it('detects Stripe live keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Stripe Live Secret Key')
    // Constructed dynamically — never stored as a literal to avoid false positives in scanners
    const fakeKey = ['sk', 'live', 'a'.repeat(24)].join('_')
    expect(matches(pattern, fakeKey)).toHaveLength(1)
    expect(matches(pattern, 'sk_test_notlive')).toHaveLength(0)
  })

  it('detects HuggingFace access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'HuggingFace Access Token')
    const token = 'hf_' + 'a'.repeat(34)
    expect(matches(pattern, `HF_TOKEN="${token}"`)).toHaveLength(1)
    expect(matches(pattern, 'hf_short')).toHaveLength(0)
  })

  it('detects Vercel access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Vercel Access Token')
    expect(matches(pattern, 'VERCEL_TOKEN="aBcDeFgHiJkLmNoPqRsTuVwX"')).toHaveLength(1)
    expect(matches(pattern, 'VERCEL_TOKEN="tooshort"')).toHaveLength(0)
  })

  it('detects Supabase service role JWTs', () => {
    const { pattern } = findPattern(credentialPatterns, 'Supabase Service Role Key')
    const header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    const payload = 'e'.repeat(70)
    const sig = 'f'.repeat(43)
    expect(matches(pattern, `${header}.${payload}.${sig}`)).toHaveLength(1)
  })

  it('detects Cloudflare API tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Cloudflare API Token')
    expect(matches(pattern, `CF_API_TOKEN="${'a'.repeat(40)}"`)).toHaveLength(1)
  })

  it('detects Azure storage connection strings', () => {
    const { pattern } = findPattern(credentialPatterns, 'Azure Storage Connection String')
    const key = 'A'.repeat(86) + '=='
    const conn = `DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=${key};EndpointSuffix=core.windows.net`
    expect(matches(pattern, conn)).toHaveLength(1)
  })

  it('detects PyPI API tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'PyPI API Token')
    const token = 'pypi-' + 'A'.repeat(50)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'pypi-tooshort')).toHaveLength(0)
  })

  it('detects Doppler service tokens', () => {
    const service = findPattern(credentialPatterns, 'Doppler Service Token')
    const token = 'dp.st.dev.' + 'A'.repeat(40)
    expect(matches(service.pattern, token)).toHaveLength(1)

    const personal = findPattern(credentialPatterns, 'Doppler Personal Token')
    const ptoken = 'dp.pt.' + 'A'.repeat(40)
    expect(matches(personal.pattern, ptoken)).toHaveLength(1)
  })

  it('detects Firebase service account key markers', () => {
    const { pattern } = findPattern(credentialPatterns, 'Firebase Service Account Key')
    const keyId = '"private_key_id": "' + 'a'.repeat(40) + '"'
    expect(matches(pattern, keyId)).toHaveLength(1)
  })

  it('detects modern OpenAI project keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'OpenAI Project Key')
    const token = 'sk-proj-' + 'a'.repeat(48)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Groq API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Groq API Key')
    const token = 'gsk_' + 'a'.repeat(52)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Stripe webhook secrets', () => {
    const { pattern } = findPattern(credentialPatterns, 'Stripe Webhook Secret')
    const token = 'whsec_' + 'a'.repeat(32)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Shopify access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Shopify Access Token')
    const token = 'shpat_' + 'a'.repeat(32)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Slack webhook URLs', () => {
    const { pattern } = findPattern(credentialPatterns, 'Slack Webhook URL')
    expect(matches(pattern, 'https://hooks.slack.com/services/T0123ABC/B0123DEF/abcdefghijklmnopqrstuvwx')).toHaveLength(1)
  })

  it('detects Discord webhook URLs', () => {
    const { pattern } = findPattern(credentialPatterns, 'Discord Webhook URL')
    expect(matches(pattern, 'https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN')).toHaveLength(1)
  })

  it('detects Telegram bot tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Telegram Bot Token')
    const token = '1234567890:AA' + 'a'.repeat(33)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects AWS temporary access keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'AWS Temporary Access Key')
    expect(matches(pattern, 'ASIAIOSFODNN7EXAMPLE')).toHaveLength(1)
  })

  it('detects DigitalOcean personal tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'DigitalOcean Personal Access Token')
    const token = 'dop_v1_' + 'a'.repeat(64)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects PlanetScale tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'PlanetScale Token')
    const token = 'pscale_tkn_' + 'a'.repeat(40)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects New Relic user API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'New Relic User API Key')
    const token = 'NRAK-' + 'A'.repeat(27)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Sentry auth tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Sentry Auth Token')
    const token = 'sntrys_' + 'a'.repeat(64)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Linear API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Linear API Key')
    const token = 'lin_api_' + 'a'.repeat(40)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Redis URLs with credentials', () => {
    const { pattern } = findPattern(credentialPatterns, 'Database URL (Redis)')
    expect(matches(pattern, 'redis://user:s3cret@localhost:6379/0')).toHaveLength(1)
  })

  it('detects PKCS8 private keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'PKCS8 Private Key')
    const block = '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----'
    expect(matches(pattern, block)).toHaveLength(1)
  })

  it('detects GitLab runner tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'GitLab Runner Token')
    const token = 'glrt-' + 'a'.repeat(20)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Mailchimp API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Mailchimp API Key')
    const token = 'a'.repeat(32) + '-us12'
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Square access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Square Access Token')
    const token = 'sq0atp-' + 'a'.repeat(22)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects OpenAI service account keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'OpenAI Service Account Key')
    const token = 'sk-svcacct-' + 'a'.repeat(48)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'sk-svcacct-short')).toHaveLength(0)
  })

  it('detects Replicate tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Replicate API Token')
    const token = 'r8_' + 'a'.repeat(37)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'r8_short')).toHaveLength(0)
  })

  it('detects Slack app tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Slack App Token')
    const token = 'xapp-1-A0123456789-1234567890123-' + 'a'.repeat(32)
    expect(matches(pattern, token)).toHaveLength(1)
  })

  it('detects Stripe restricted keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Stripe Restricted Key')
    const token = ['rk', 'live', 'a'.repeat(24)].join('_')
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'rk_test_abc')).toHaveLength(0)
  })

  it('detects Shopify shared secrets and app tokens', () => {
    const shared = findPattern(credentialPatterns, 'Shopify Shared Secret')
    const custom = findPattern(credentialPatterns, 'Shopify Custom App Token')
    const privateApp = findPattern(credentialPatterns, 'Shopify Private App Token')
    expect(matches(shared.pattern, 'shpss_' + 'a'.repeat(32))).toHaveLength(1)
    expect(matches(custom.pattern, 'shpca_' + 'a'.repeat(32))).toHaveLength(1)
    expect(matches(privateApp.pattern, 'shppa_' + 'a'.repeat(32))).toHaveLength(1)
  })

  it('detects Square OAuth secrets', () => {
    const { pattern } = findPattern(credentialPatterns, 'Square OAuth Secret')
    expect(matches(pattern, 'sq0csp-' + 'a'.repeat(22))).toHaveLength(1)
  })

  it('detects Mailgun keys only with Mailgun context', () => {
    const entry = findPattern(credentialPatterns, 'Mailgun API Key')
    const key = 'key-' + 'a'.repeat(32)
    expect(matches(entry.pattern, `MAILGUN_API_KEY="${key}"`)).toHaveLength(1)
    expect(matches(entry.pattern, key)).toHaveLength(0)
  })

  it('detects Resend API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Resend API Key')
    expect(matches(pattern, 're_' + 'a'.repeat(24))).toHaveLength(1)
    expect(matches(pattern, 're_short')).toHaveLength(0)
  })

  it('detects Postmark server tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Postmark Server Token')
    const token = 'a'.repeat(8) + '-' + 'b'.repeat(4) + '-' + 'c'.repeat(4) + '-' + 'd'.repeat(4) + '-' + 'e'.repeat(12)
    expect(matches(pattern, `POSTMARK_SERVER_TOKEN="${token}"`)).toHaveLength(1)
  })

  it('detects AMQP URLs with credentials', () => {
    const { pattern } = findPattern(credentialPatterns, 'AMQP URL')
    expect(matches(pattern, 'amqp://user:pass@localhost:5672/vhost')).toHaveLength(1)
    expect(matches(pattern, 'amqp://localhost:5672')).toHaveLength(0)
  })

  it('detects DSA private keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'DSA Private Key')
    const block = '-----BEGIN DSA PRIVATE KEY-----\nMIIE\n-----END DSA PRIVATE KEY-----'
    expect(matches(pattern, block)).toHaveLength(1)
  })

  it('detects GitLab deploy and OAuth secrets', () => {
    const deploy = findPattern(credentialPatterns, 'GitLab Deploy Token')
    const oauth = findPattern(credentialPatterns, 'GitLab OAuth App Secret')
    expect(matches(deploy.pattern, 'gldt-' + 'a'.repeat(20))).toHaveLength(1)
    expect(matches(oauth.pattern, 'gloas-' + 'a'.repeat(20))).toHaveLength(1)
  })

  it('detects DigitalOcean OAuth and Netlify tokens', () => {
    const digitalOcean = findPattern(credentialPatterns, 'DigitalOcean OAuth Token')
    const netlify = findPattern(credentialPatterns, 'Netlify Access Token')
    expect(matches(digitalOcean.pattern, 'doo_v1_' + 'a'.repeat(64))).toHaveLength(1)
    expect(matches(netlify.pattern, 'nf_' + 'a'.repeat(40))).toHaveLength(1)
    expect(matches(netlify.pattern, 'nf_flag')).toHaveLength(0)
  })

  it('detects Terraform Pulumi and Vault tokens', () => {
    const terraform = findPattern(credentialPatterns, 'Terraform Cloud Token')
    const pulumi = findPattern(credentialPatterns, 'Pulumi Access Token')
    const vault = findPattern(credentialPatterns, 'HashiCorp Vault Token')
    expect(matches(terraform.pattern, 'at.' + 'a'.repeat(50))).toHaveLength(1)
    expect(matches(terraform.pattern, 'email at.company.com')).toHaveLength(0)
    expect(matches(pulumi.pattern, 'pul-' + 'a'.repeat(40))).toHaveLength(1)
    expect(matches(vault.pattern, 'hvs.' + 'a'.repeat(24))).toHaveLength(1)
  })

  it('detects Sentry DSN and New Relic license keys', () => {
    const sentry = findPattern(credentialPatterns, 'Sentry DSN')
    const license = findPattern(credentialPatterns, 'New Relic License Key')
    expect(matches(sentry.pattern, 'https://abcd1234@o123.ingest.sentry.io/456')).toHaveLength(1)
    expect(matches(license.pattern, 'a'.repeat(32) + 'NRAL')).toHaveLength(1)
  })

  it('detects Datadog Notion Postman Dropbox Mapbox tokens', () => {
    const datadog = findPattern(credentialPatterns, 'Datadog API Key')
    const notion = findPattern(credentialPatterns, 'Notion Integration Token')
    const postman = findPattern(credentialPatterns, 'Postman API Key')
    const dropbox = findPattern(credentialPatterns, 'Dropbox Access Token')
    const mapbox = findPattern(credentialPatterns, 'Mapbox Secret Token')
    expect(matches(datadog.pattern, `DD_API_KEY="${'a'.repeat(32)}"`)).toHaveLength(1)
    expect(matches(notion.pattern, 'ntn_' + 'a'.repeat(40))).toHaveLength(1)
    expect(matches(postman.pattern, 'PMAK-' + 'a'.repeat(24) + '-' + 'b'.repeat(34))).toHaveLength(1)
    expect(matches(dropbox.pattern, 'sl.' + 'a'.repeat(100))).toHaveLength(1)
    expect(matches(dropbox.pattern, 'sl.short')).toHaveLength(0)
    expect(matches(mapbox.pattern, 'sk.' + 'a'.repeat(60))).toHaveLength(1)
  })

  it('detects Algolia Contentful Heroku and GCP markers', () => {
    const algolia = findPattern(credentialPatterns, 'Algolia API Key')
    const contentful = findPattern(credentialPatterns, 'Contentful Access Token')
    const heroku = findPattern(credentialPatterns, 'Heroku API Key')
    const gcp = findPattern(credentialPatterns, 'GCP Service Account Email')
    expect(matches(algolia.pattern, `ALGOLIA_API_KEY="${'a'.repeat(32)}"`)).toHaveLength(1)
    expect(matches(contentful.pattern, `CONTENTFUL_ACCESS_TOKEN="${'a'.repeat(40)}"`)).toHaveLength(1)
    expect(matches(heroku.pattern, `HEROKU_API_KEY="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"`)).toHaveLength(1)
    expect(matches(gcp.pattern, '"client_email": "svc@my-project.iam.gserviceaccount.com"')).toHaveLength(1)
  })

  it('filters placeholder generic API keys', () => {
    const entry = findPattern(credentialPatterns, 'Generic API Key')
    const real = matches(entry.pattern, `api_key="${'aB3x'.repeat(10)}"`)
    expect(real.length).toBeGreaterThan(0)
    expect(entry.filter!(real[0]!)).toBe(true)

    const placeholder = matches(entry.pattern, 'api_key="YOUR_API_KEY_PLACEHOLDER_VALUE_HERE_123456"')
    expect(placeholder.length).toBeGreaterThan(0)
    expect(entry.filter!(placeholder[0]!)).toBe(false)

    const fromEnv = matches(entry.pattern, 'api_key=process.env.API_KEY_VALUE_WITH_LONG_SUFFIX_123456')
    // process.env form may not match length rules; if it does, filter must reject
    if (fromEnv[0]) expect(entry.filter!(fromEnv[0])).toBe(false)
  })

  it('ignores redis urls without credentials', () => {
    const { pattern } = findPattern(credentialPatterns, 'Database URL (Redis)')
    expect(matches(pattern, 'redis://localhost:6379')).toHaveLength(0)
  })

  it('detects JWT tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'JWT Token')
    const token = 'eyJ' + 'a'.repeat(12) + '.eyJ' + 'b'.repeat(12) + '.' + 'c'.repeat(12)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'eyJtoo.short.jwt')).toHaveLength(0)
  })

  it('detects legacy OpenAI API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'OpenAI API Key')
    const token = 'sk-' + 'a'.repeat(20) + 'T3BlbkFJ' + 'b'.repeat(20)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'sk-short')).toHaveLength(0)
  })

  it('detects Anthropic API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Anthropic API Key')
    const token = 'sk-ant-' + 'a'.repeat(93)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'sk-ant-short')).toHaveLength(0)
  })

  it('detects Slack bot and user tokens', () => {
    const bot = findPattern(credentialPatterns, 'Slack Bot Token')
    const user = findPattern(credentialPatterns, 'Slack User Token')
    expect(matches(bot.pattern, 'xoxb-1234567890-1234567890-' + 'a'.repeat(24))).toHaveLength(1)
    expect(matches(user.pattern, 'xoxp-1234567890-1234567890-1234567890-' + 'a'.repeat(32))).toHaveLength(1)
    expect(matches(bot.pattern, 'xoxb-short')).toHaveLength(0)
  })

  it('detects Discord bot tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'Discord Bot Token')
    const token = 'M' + 'a'.repeat(23) + '.' + 'b'.repeat(6) + '.' + 'c'.repeat(27)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'M.short.token')).toHaveLength(0)
  })

  it('detects AWS secret keys with assignment context', () => {
    const { pattern } = findPattern(credentialPatterns, 'AWS Secret Key')
    expect(matches(pattern, `AWS_SECRET_ACCESS_KEY=${'A'.repeat(40)}`)).toHaveLength(1)
    expect(matches(pattern, 'A'.repeat(40))).toHaveLength(0)
  })

  it('detects GitHub app and OAuth tokens', () => {
    const app = findPattern(credentialPatterns, 'GitHub App Token')
    const oauth = findPattern(credentialPatterns, 'GitHub OAuth Token')
    expect(matches(app.pattern, 'ghs_' + 'a'.repeat(36))).toHaveLength(1)
    expect(matches(oauth.pattern, 'gho_' + 'a'.repeat(36))).toHaveLength(1)
    expect(matches(app.pattern, 'ghs_short')).toHaveLength(0)
  })

  it('detects Stripe live publishable keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Stripe Live Publishable Key')
    const token = ['pk', 'live', 'a'.repeat(24)].join('_')
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'pk_test_abc')).toHaveLength(0)
  })

  it('detects SendGrid API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'SendGrid API Key')
    const token = 'SG.' + 'a'.repeat(22) + '.' + 'b'.repeat(43)
    expect(matches(pattern, token)).toHaveLength(1)
    expect(matches(pattern, 'SG.short')).toHaveLength(0)
  })

  it('detects npm access tokens', () => {
    const { pattern } = findPattern(credentialPatterns, 'npm Access Token')
    expect(matches(pattern, 'npm_' + 'a'.repeat(36))).toHaveLength(1)
    expect(matches(pattern, 'npm_short')).toHaveLength(0)
  })

  it('detects Google API keys', () => {
    const { pattern } = findPattern(credentialPatterns, 'Google API Key')
    expect(matches(pattern, 'AIzaSy' + 'a'.repeat(33))).toHaveLength(1)
    expect(matches(pattern, 'AIzaSyShort')).toHaveLength(0)
  })

  it('detects Postgres MySQL and Mongo URLs with credentials', () => {
    const postgres = findPattern(credentialPatterns, 'Database URL (PostgreSQL)')
    const mysql = findPattern(credentialPatterns, 'Database URL (MySQL)')
    const mongo = findPattern(credentialPatterns, 'Database URL (MongoDB)')
    expect(matches(postgres.pattern, 'postgres://user:pass@localhost:5432/db')).toHaveLength(1)
    expect(matches(mysql.pattern, 'mysql://user:pass@localhost:3306/db')).toHaveLength(1)
    expect(matches(mongo.pattern, 'mongodb://user:pass@localhost:27017/db')).toHaveLength(1)
    expect(matches(postgres.pattern, 'postgres://localhost:5432/db')).toHaveLength(0)
  })

  it('detects RSA EC OpenSSH and PGP private keys', () => {
    const rsa = findPattern(credentialPatterns, 'RSA Private Key')
    const ec = findPattern(credentialPatterns, 'EC Private Key')
    const openssh = findPattern(credentialPatterns, 'OpenSSH Private Key')
    const pgp = findPattern(credentialPatterns, 'PGP Private Key')
    expect(matches(rsa.pattern, '-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----')).toHaveLength(1)
    expect(matches(ec.pattern, '-----BEGIN EC PRIVATE KEY-----\nMIIE\n-----END EC PRIVATE KEY-----')).toHaveLength(1)
    expect(matches(openssh.pattern, '-----BEGIN OPENSSH PRIVATE KEY-----\nMIIE\n-----END OPENSSH PRIVATE KEY-----')).toHaveLength(1)
    expect(matches(pgp.pattern, '-----BEGIN PGP PRIVATE KEY BLOCK-----\nMIIE\n-----END PGP PRIVATE KEY BLOCK-----')).toHaveLength(1)
  })

  it('detects GitLab PATs and GitHub fine-grained tokens', () => {
    const gitlab = findPattern(credentialPatterns, 'GitLab Personal Access Token')
    const fine = findPattern(credentialPatterns, 'GitHub Fine-Grained Token')
    expect(matches(gitlab.pattern, 'glpat-' + 'a'.repeat(20))).toHaveLength(1)
    expect(matches(fine.pattern, 'github_pat_' + 'a'.repeat(82))).toHaveLength(1)
    expect(matches(gitlab.pattern, 'glpat-short')).toHaveLength(0)
  })

  it('detects Twilio SID and auth tokens', () => {
    const sid = findPattern(credentialPatterns, 'Twilio Account SID')
    const auth = findPattern(credentialPatterns, 'Twilio Auth Token')
    expect(matches(sid.pattern, 'AC' + 'a'.repeat(32))).toHaveLength(1)
    expect(matches(auth.pattern, `TWILIO_AUTH_TOKEN="${'a'.repeat(32)}"`)).toHaveLength(1)
    expect(matches(sid.pattern, 'ACshort')).toHaveLength(0)
  })

  it('detects Cloudflare global keys Azure client secrets and Firebase web keys', () => {
    const cloudflare = findPattern(credentialPatterns, 'Cloudflare Global API Key')
    const azure = findPattern(credentialPatterns, 'Azure Client Secret')
    const firebase = findPattern(credentialPatterns, 'Firebase Web API Key')
    expect(matches(cloudflare.pattern, `CF_API_KEY="${'a'.repeat(37)}"`)).toHaveLength(1)
    expect(matches(azure.pattern, `AZURE_CLIENT_SECRET="${'a'.repeat(34)}"`)).toHaveLength(1)
    expect(matches(firebase.pattern, `FIREBASE_API_KEY="AIzaSy${'a'.repeat(33)}"`)).toHaveLength(1)
  })
})

describe('Remaining PII pattern coverage', () => {
  it('detects international phone numbers', () => {
    const entry = findPattern(piiPatterns, 'Phone Number (International)')
    expect(matches(entry.pattern, '+44 20 7946 0958').length).toBeGreaterThan(0)
    expect(entry.filter!('+44 20 7946 0958')).toBe(true)
    expect(entry.filter!('+1 555 123 4567')).toBe(false)
  })

  it('detects public IPv4 addresses and skips private ranges', () => {
    const { pattern } = findPattern(piiPatterns, 'IPv4 Address')
    expect(matches(pattern, '8.8.8.8')).toHaveLength(1)
    expect(matches(pattern, '192.168.1.1')).toHaveLength(0)
    expect(matches(pattern, '10.0.0.1')).toHaveLength(0)
    expect(matches(pattern, '127.0.0.1')).toHaveLength(0)
  })
})

describe('Full detector coverage', () => {
  it('has a direct findPattern test for every detector', () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'patterns.test.ts'), 'utf-8')
    const tested = new Set([...source.matchAll(/findPattern\([^,]+,\s*'([^']+)'\)/g)].map((match) => match[1]))
    const allNames = [...credentialPatterns, ...piiPatterns].map((pattern) => pattern.name)
    const missing = allNames.filter((name) => !tested.has(name))
    expect(missing).toEqual([])
  })
})

describe('Ignorefile', () => {
  it('loads patterns from .secretguardignore', async () => {
    const dir = tmpdir()
    const filePath = join(dir, '.secretguardignore')
    await writeFile(filePath, '# comment\nnode_modules\ndist\n\n.env\n', 'utf-8')
    const patterns = await loadIgnoreFile(dir)
    expect(patterns).toEqual(['node_modules', 'dist', '.env'])
    await unlink(filePath)
  })

  it('returns empty array when file is missing', async () => {
    const patterns = await loadIgnoreFile('/tmp/does-not-exist-secretguard-test')
    expect(patterns).toEqual([])
  })
})

describe('Baseline', () => {
  it('filters findings present in baseline', async () => {
    const { filterBaseline, writeBaseline, loadBaseline } = await import('../src/baseline.js')
    const baselinePath = join(tmpdir(), `sg-baseline-test-${Date.now()}.json`)

    const finding = {
      file: 'src/config.ts',
      line: 10,
      column: 5,
      pattern: 'AWS Access Key',
      severity: 'CRITICAL' as const,
      masked: 'AKIA***EXAMPLE',
      raw: 'AKIAIOSFODNN7EXAMPLE',
    }

    await writeBaseline(baselinePath, [finding])
    const baseline = await loadBaseline(baselinePath)
    const filtered = filterBaseline([finding], baseline)

    expect(filtered).toHaveLength(0)
    await unlink(baselinePath)
  })

  it('keeps findings not in baseline', async () => {
    const { filterBaseline } = await import('../src/baseline.js')
    const finding = {
      file: 'src/config.ts',
      line: 10,
      column: 5,
      pattern: 'AWS Access Key',
      severity: 'CRITICAL' as const,
      masked: 'AKIA***EXAMPLE',
      raw: 'AKIAIOSFODNN7EXAMPLE',
    }

    const filtered = filterBaseline([finding], new Set())
    expect(filtered).toHaveLength(1)
  })
})

describe('SARIF reporter', () => {
  it('generates valid SARIF 2.1.0 structure', async () => {
    const { generateSarif } = await import('../src/reporter/sarif.js')

    const result = {
      scanned: 1,
      duration: 100,
      findings: [
        {
          file: 'src/index.ts',
          line: 5,
          column: 3,
          pattern: 'AWS Access Key',
          severity: 'CRITICAL' as const,
          masked: 'AKIA***',
          raw: 'AKIAIOSFODNN7EXAMPLE',
        },
      ],
    }

    const sarif = JSON.parse(generateSarif(result))

    expect(sarif.version).toBe('2.1.0')
    expect(sarif.runs).toHaveLength(1)
    expect(sarif.runs[0].tool.driver.name).toBe('secretguard')
    expect(sarif.runs[0].results).toHaveLength(1)
    expect(sarif.runs[0].results[0].ruleId).toBe('AWS Access Key')
    expect(sarif.runs[0].results[0].level).toBe('error')
  })
})
