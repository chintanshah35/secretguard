import { describe, it, expect, vi } from 'vitest'
import { verifyFindings, canVerify } from '../src/verify.js'
import type { Finding } from '../src/patterns/types.js'

function finding(partial: Partial<Finding> & Pick<Finding, 'pattern' | 'raw'>): Finding {
  return {
    file: 'secrets.env',
    line: 1,
    column: 1,
    severity: 'CRITICAL',
    masked: '****',
    ...partial,
  }
}

describe('verifyFindings', () => {
  it('marks supported providers', () => {
    expect(canVerify('OpenAI API Key')).toBe(true)
    expect(canVerify('Email Address')).toBe(false)
  })

  it('confirms a live OpenAI key', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }))
    const results = await verifyFindings(
      [finding({ pattern: 'OpenAI API Key', raw: 'sk-testkey' })],
      { fetchImpl: fetchImpl as unknown as typeof fetch },
    )
    expect(results[0]?.verification?.status).toBe('confirmed')
    expect(fetchImpl).toHaveBeenCalled()
  })

  it('marks rejected OpenAI keys invalid', async () => {
    const fetchImpl = vi.fn(async () => new Response('unauthorized', { status: 401 }))
    const results = await verifyFindings(
      [finding({ pattern: 'OpenAI Project Key', raw: 'sk-proj-test' })],
      { fetchImpl: fetchImpl as unknown as typeof fetch },
    )
    expect(results[0]?.verification?.status).toBe('invalid')
  })

  it('confirms GitHub tokens', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }))
    const results = await verifyFindings(
      [finding({ pattern: 'GitHub Personal Access Token', raw: 'ghp_test' })],
      { fetchImpl: fetchImpl as unknown as typeof fetch },
    )
    expect(results[0]?.verification?.status).toBe('confirmed')
  })

  it('confirms Stripe secrets', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 200 }))
    const results = await verifyFindings(
      [finding({ pattern: 'Stripe Live Secret Key', raw: 'sk_live_test' })],
      { fetchImpl: fetchImpl as unknown as typeof fetch },
    )
    expect(results[0]?.verification?.status).toBe('confirmed')
  })

  it('skips AWS access keys without a paired secret', async () => {
    const results = await verifyFindings([
      finding({ pattern: 'AWS Access Key', raw: 'AKIAIOSFODNN7EXAMPLE' }),
    ])
    expect(results[0]?.verification?.status).toBe('skipped')
  })

  it('marks unsupported patterns', async () => {
    const results = await verifyFindings([
      finding({ pattern: 'npm Access Token', raw: 'npm_test', severity: 'CRITICAL' }),
    ])
    expect(results[0]?.verification?.status).toBe('unsupported')
  })
})
