#!/usr/bin/env node

import { parseArgs } from './args.js'
import { scan } from '../scanner/index.js'
import { printReport } from '../reporter/terminal.js'
import { printJson } from '../reporter/json.js'

const args = parseArgs(process.argv)

if (args.help) {
  console.log(`
secretscan — scan source code for secrets, credentials, and PII

Usage:
  secretscan [path] [options]

Options:
  --ignore, -i <path>   Ignore a path (repeatable)
  --json                Output results as JSON
  --output, -o <file>   Save HTML report to file
  --help, -h            Show this help message

Examples:
  secretscan .
  secretscan ./src --ignore tests
  secretscan . --json
  secretscan . --output report.html
  `)
  process.exit(0)
}

const result = await scan(args.target, { ignore: args.ignore })

if (args.json) {
  printJson(result)
} else {
  printReport(result)
}
