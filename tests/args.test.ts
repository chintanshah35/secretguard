import { describe, it, expect } from 'vitest'
import { parseArgs } from '../src/cli/args.js'

describe('parseArgs', () => {
  it('parses --verify', () => {
    const args = parseArgs(['node', 'secretguard', '.', '--verify'])
    expect(args.verify).toBe(true)
    expect(args.target).toBe('.')
  })

  it('defaults verify to false', () => {
    const args = parseArgs(['node', 'secretguard', './src'])
    expect(args.verify).toBe(false)
  })
})
