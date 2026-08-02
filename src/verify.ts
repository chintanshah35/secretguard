import type { Finding, Verification } from './patterns/types.js'

export type VerifyOptions = {
  fetchImpl?: typeof fetch
  timeoutMs?: number
}

const VERIFY_PATTERNS = new Set([
  'OpenAI API Key',
  'OpenAI Project Key',
  'OpenAI Service Account Key',
  'Anthropic API Key',
  'GitHub Personal Access Token',
  'GitHub Fine-Grained Token',
  'GitHub App Token',
  'GitHub OAuth Token',
  'Stripe Live Secret Key',
  'Stripe Restricted Key',
  'AWS Access Key',
  'AWS Temporary Access Key',
])

function canVerify(patternName: string) {
  return VERIFY_PATTERNS.has(patternName)
}

async function request(
  url: string,
  init: RequestInit,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timer)
  }
}

async function verifyOpenAI(
  token: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Verification> {
  try {
    const response = await request(
      'https://api.openai.com/v1/models',
      {
        headers: { Authorization: `Bearer ${token}` },
      },
      fetchImpl,
      timeoutMs,
    )
    if (response.status === 200) {
      return { status: 'confirmed', detail: 'OpenAI accepted this key' }
    }
    if (response.status === 401 || response.status === 403) {
      return { status: 'invalid', detail: 'OpenAI rejected this key' }
    }
    return { status: 'error', detail: `OpenAI returned HTTP ${response.status}` }
  } catch (error) {
    return { status: 'error', detail: `OpenAI verify failed: ${String(error)}` }
  }
}

async function verifyAnthropic(
  token: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Verification> {
  try {
    const response = await request(
      'https://api.anthropic.com/v1/models',
      {
        headers: {
          'x-api-key': token,
          'anthropic-version': '2023-06-01',
        },
      },
      fetchImpl,
      timeoutMs,
    )
    if (response.status === 200) {
      return { status: 'confirmed', detail: 'Anthropic accepted this key' }
    }
    if (response.status === 401 || response.status === 403) {
      return { status: 'invalid', detail: 'Anthropic rejected this key' }
    }
    return { status: 'error', detail: `Anthropic returned HTTP ${response.status}` }
  } catch (error) {
    return { status: 'error', detail: `Anthropic verify failed: ${String(error)}` }
  }
}

async function verifyGitHub(
  token: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Verification> {
  try {
    const response = await request(
      'https://api.github.com/user',
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'secretguard-verify',
        },
      },
      fetchImpl,
      timeoutMs,
    )
    if (response.status === 200) {
      return { status: 'confirmed', detail: 'GitHub accepted this token' }
    }
    if (response.status === 401 || response.status === 403) {
      return { status: 'invalid', detail: 'GitHub rejected this token' }
    }
    return { status: 'error', detail: `GitHub returned HTTP ${response.status}` }
  } catch (error) {
    return { status: 'error', detail: `GitHub verify failed: ${String(error)}` }
  }
}

async function verifyStripe(
  token: string,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Verification> {
  try {
    const response = await request(
      'https://api.stripe.com/v1/balance',
      {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
      fetchImpl,
      timeoutMs,
    )
    if (response.status === 200) {
      return { status: 'confirmed', detail: 'Stripe accepted this key' }
    }
    if (response.status === 401 || response.status === 403) {
      return { status: 'invalid', detail: 'Stripe rejected this key' }
    }
    return { status: 'error', detail: `Stripe returned HTTP ${response.status}` }
  } catch (error) {
    return { status: 'error', detail: `Stripe verify failed: ${String(error)}` }
  }
}

async function verifyAwsAccessKey(
  accessKey: string,
  secretKey: string | undefined,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Verification> {
  if (!secretKey) {
    return {
      status: 'skipped',
      detail: 'AWS verify needs a matching secret key in the same scan',
    }
  }

  // STS GetCallerIdentity via unsigned-style probe is not possible without SigV4.
  // Use a minimal SigV4-free check: AWS returns InvalidClientTokenId vs SignatureDoesNotMatch.
  const body = 'Action=GetCallerIdentity&Version=2011-06-15'
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '')
  const dateStamp = amzDate.slice(0, 8)

  try {
    const { Authorization } = await signAwsRequest({
      accessKey,
      secretKey,
      amzDate,
      dateStamp,
      body,
    })

    const response = await request(
      'https://sts.amazonaws.com/',
      {
        method: 'POST',
        headers: {
          Authorization,
          'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
          Host: 'sts.amazonaws.com',
          'X-Amz-Date': amzDate,
        },
        body,
      },
      fetchImpl,
      timeoutMs,
    )

    const text = await response.text()
    if (response.status === 200 && text.includes('GetCallerIdentityResponse')) {
      return { status: 'confirmed', detail: 'AWS STS accepted this access key pair' }
    }
    if (text.includes('InvalidClientTokenId') || text.includes('InvalidAccessKeyId')) {
      return { status: 'invalid', detail: 'AWS rejected this access key id' }
    }
    if (text.includes('SignatureDoesNotMatch')) {
      return { status: 'invalid', detail: 'AWS rejected this secret key signature' }
    }
    return {
      status: 'error',
      detail: `AWS STS returned HTTP ${response.status}`,
    }
  } catch (error) {
    return { status: 'error', detail: `AWS verify failed: ${String(error)}` }
  }
}

async function signAwsRequest(input: {
  accessKey: string
  secretKey: string
  amzDate: string
  dateStamp: string
  body: string
}) {
  const encoder = new TextEncoder()
  const region = 'us-east-1'
  const service = 'sts'
  const method = 'POST'
  const canonicalUri = '/'
  const canonicalQuerystring = ''
  const payloadHash = await sha256Hex(input.body)
  const canonicalHeaders =
    `content-type:application/x-www-form-urlencoded; charset=utf-8\n` +
    `host:sts.amazonaws.com\n` +
    `x-amz-date:${input.amzDate}\n`
  const signedHeaders = 'content-type;host;x-amz-date'
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n')

  const credentialScope = `${input.dateStamp}/${region}/${service}/aws4_request`
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    input.amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join('\n')

  const signingKey = await getSignatureKey(input.secretKey, input.dateStamp, region, service)
  const signature = await hmacHex(signingKey, stringToSign)
  const Authorization =
    `AWS4-HMAC-SHA256 Credential=${input.accessKey}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`

  return { Authorization, payloadHash }
}

async function sha256Hex(value: string) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return bufferToHex(digest)
}

async function hmac(key: BufferSource, value: string) {
  const keyBytes =
    key instanceof ArrayBuffer
      ? new Uint8Array(key)
      : new Uint8Array(key.buffer, key.byteOffset, key.byteLength)
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(value))
}

async function hmacHex(key: ArrayBuffer, value: string) {
  return bufferToHex(await hmac(key, value))
}

async function getSignatureKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string,
) {
  const keyDate = await hmac(new TextEncoder().encode(`AWS4${secretKey}`), dateStamp)
  const keyRegion = await hmac(keyDate, region)
  const keyService = await hmac(keyRegion, service)
  return hmac(keyService, 'aws4_request')
}

function bufferToHex(buffer: ArrayBuffer) {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

async function verifyOne(
  finding: Finding,
  secretByAccessKey: Map<string, string>,
  fetchImpl: typeof fetch,
  timeoutMs: number,
): Promise<Verification> {
  if (!canVerify(finding.pattern)) {
    return {
      status: 'unsupported',
      detail: 'Live verify supports OpenAI, Anthropic, GitHub, Stripe, and AWS access keys',
    }
  }

  if (finding.pattern.startsWith('OpenAI')) {
    return verifyOpenAI(finding.raw, fetchImpl, timeoutMs)
  }
  if (finding.pattern === 'Anthropic API Key') {
    return verifyAnthropic(finding.raw, fetchImpl, timeoutMs)
  }
  if (finding.pattern.startsWith('GitHub')) {
    return verifyGitHub(finding.raw, fetchImpl, timeoutMs)
  }
  if (finding.pattern.startsWith('Stripe')) {
    return verifyStripe(finding.raw, fetchImpl, timeoutMs)
  }
  if (finding.pattern === 'AWS Access Key' || finding.pattern === 'AWS Temporary Access Key') {
    return verifyAwsAccessKey(
      finding.raw,
      secretByAccessKey.get(finding.raw),
      fetchImpl,
      timeoutMs,
    )
  }

  return { status: 'unsupported', detail: 'No verifier for this pattern' }
}

function collectAwsSecrets(findings: Finding[]) {
  const secrets = findings
    .filter((finding) => finding.pattern === 'AWS Secret Key')
    .map((finding) => finding.raw)

  // Pairing is best-effort: if exactly one secret is present, use it for all access keys.
  // Otherwise leave pairing empty and AWS checks will be skipped.
  const secretByAccessKey = new Map<string, string>()
  if (secrets.length === 1) {
    const onlySecret = secrets[0]!
    for (const finding of findings) {
      if (finding.pattern === 'AWS Access Key' || finding.pattern === 'AWS Temporary Access Key') {
        secretByAccessKey.set(finding.raw, onlySecret)
      }
    }
  }
  return secretByAccessKey
}

/**
 * Optionally call provider APIs to mark findings confirmed or invalid.
 * Only a small set of high-value providers is supported.
 */
export async function verifyFindings(
  findings: Finding[],
  options: VerifyOptions = {},
): Promise<Finding[]> {
  const fetchImpl = options.fetchImpl ?? fetch
  const timeoutMs = options.timeoutMs ?? 8000
  const secretByAccessKey = collectAwsSecrets(findings)

  const verified: Finding[] = []
  for (const finding of findings) {
    const verification = await verifyOne(finding, secretByAccessKey, fetchImpl, timeoutMs)
    verified.push({ ...finding, verification })
  }
  return verified
}

export { canVerify }
