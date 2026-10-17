import { describe, it, expect } from 'vitest'
import { parseArgs } from '../src/cli/args.js'

const parse = (...argv: string[]) => parseArgs(['node', 'secretguard', ...argv])

describe('parseArgs', () => {
  it('parses --verify', () => {
    const args = parse('.', '--verify')
    expect(args.verify).toBe(true)
    expect(args.target).toBe('.')
  })

  it('defaults verify to false', () => {
    const args = parse('./src')
    expect(args.verify).toBe(false)
  })

  it('defaults to failing on critical with PII and gitignore on', () => {
    const args = parse('.')
    expect(args.failOn).toBe('CRITICAL')
    expect(args.pii).toBe(true)
    expect(args.gitignore).toBe(true)
  })

  it('parses --no-pii, --no-gitignore and --fail-on', () => {
    const args = parse('.', '--no-pii', '--no-gitignore', '--fail-on', 'medium')
    expect(args.pii).toBe(false)
    expect(args.gitignore).toBe(false)
    expect(args.failOn).toBe('MEDIUM')
  })

  it('rejects an invalid --fail-on value', () => {
    expect(() => parse('.', '--fail-on', 'urgent')).toThrow(/--fail-on expects/)
  })

  it('rejects unknown flags', () => {
    expect(() => parse('.', '--no-pi')).toThrow('unknown option "--no-pi"')
  })

  it('rejects flags missing their value', () => {
    expect(() => parse('.', '--ignore', '--json')).toThrow('--ignore needs a value')
    expect(() => parse('.', '--sarif')).toThrow('--sarif needs a value')
  })
})
