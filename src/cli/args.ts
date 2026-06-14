export type CliArgs = {
  target: string
  ignore: string[]
  json: boolean
  output: string | null
  history: boolean
  staged: boolean
  installHook: boolean
  help: boolean
}

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
    help: false,
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
    } else if (arg === 'install-hook') {
      result.installHook = true
    } else if (arg === '--ignore' || arg === '-i') {
      const value = args[++index]
      if (value) result.ignore.push(value)
    } else if (arg === '--output' || arg === '-o') {
      result.output = args[++index] ?? null
    } else if (!arg.startsWith('-')) {
      result.target = arg
    }
  }

  return result
}
