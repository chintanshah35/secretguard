import type { Severity } from '../patterns/types.js'

export type CliArgs = {
  target: string
  ignore: string[]
  json: boolean
  output: string | null
  history: boolean
  staged: boolean
  installHook: boolean
  sarif: string | null
  baseline: string | null
  updateBaseline: boolean
  verify: boolean
  gitignore: boolean
  pii: boolean
  failOn: Severity
  help: boolean
}

const SEVERITIES: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

export function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2)
  const result: CliArgs = {
    target: '.',
    ignore: [],
    json: false,
    output: null,
    history: false,
    staged: false,
    installHook: false,
    sarif: null,
    baseline: null,
    updateBaseline: false,
    verify: false,
    gitignore: true,
    pii: true,
    failOn: 'CRITICAL',
    help: false,
  }

  const valueFor = (flag: string, index: number) => {
    const value = args[index]
    if (value === undefined || value.startsWith('-')) throw new Error(`${flag} needs a value`)
    return value
  }

  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!
    if (arg === '--help' || arg === '-h') {
      result.help = true
    } else if (arg === '--json') {
      result.json = true
    } else if (arg === '--history') {
      result.history = true
    } else if (arg === '--staged') {
      result.staged = true
    } else if (arg === '--verify') {
      result.verify = true
    } else if (arg === 'install-hook') {
      result.installHook = true
    } else if (arg === '--sarif') {
      result.sarif = valueFor(arg, ++index)
    } else if (arg === '--baseline') {
      result.baseline = valueFor(arg, ++index)
    } else if (arg === '--no-gitignore') {
      result.gitignore = false
    } else if (arg === '--no-pii') {
      result.pii = false
    } else if (arg === '--fail-on') {
      const value = args[++index]?.toUpperCase()
      if (!SEVERITIES.includes(value as Severity)) {
        throw new Error(`--fail-on expects one of ${SEVERITIES.join(', ').toLowerCase()}, got "${args[index] ?? ''}"`)
      }
      result.failOn = value as Severity
    } else if (arg === '--update-baseline') {
      result.updateBaseline = true
    } else if (arg === '--ignore' || arg === '-i') {
      result.ignore.push(valueFor(arg, ++index))
    } else if (arg === '--output' || arg === '-o') {
      result.output = valueFor(arg, ++index)
    } else if (arg.startsWith('-')) {
      throw new Error(`unknown option "${arg}"`)
    } else {
      result.target = arg
    }
  }

  return result
}
