import { describe, it, expect } from 'vitest'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { scan } from '../src/scanner/index.js'

const fixtureRoot = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'clean-project')

describe('False positive fixture', () => {
  it('stays clean on a normal Node project', async () => {
    const result = await scan(fixtureRoot)

    expect(result.scanned).toBeGreaterThan(0)
    expect(result.findings).toEqual([])
  })
})
