#!/usr/bin/env node

import { writeFile } from 'fs/promises'
import { parseArgs } from './args.js'
import { scan } from '../scanner/index.js'
import { scanHistory } from '../scanner/history.js'
import { printReport } from '../reporter/terminal.js'
import { printHistoryReport } from '../reporter/terminal.js'
import { printJson } from '../reporter/json.js'
import { printHistoryJson } from '../reporter/json.js'
import { generateHtml } from '../reporter/html.js'

const args = parseArgs(process.argv)

if (args.help) {
  console.log(`
secretguard — scan source code for secrets, credentials, and PII

Usage:
  secretguard [path] [options]

Options:
  --ignore, -i <path>   Ignore a path (repeatable)
  --json                Output results as JSON
  --history             Scan full git commit history
  --output, -o <file>   Save HTML report to file
  --help, -h            Show this help message

Examples:
  secretguard .
  secretguard ./src --ignore tests
  secretguard . --json
  secretguard . --history
  secretguard . --history --json
  secretguard . --output report.html
  `)
  process.exit(0)
}

if (args.history) {
  const result = await scanHistory(args.target)

  if (args.json) {
    printHistoryJson(result)
  } else {
    printHistoryReport(result)
  }

  const hasCritical = result.findings.some((f) => f.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
} else {
  const result = await scan(args.target, { ignore: args.ignore })

  if (args.output) {
    const html = generateHtml(result)
    await writeFile(args.output, html, 'utf-8')
    console.log(`Report saved to ${args.output}`)
  }

  if (args.json) {
    printJson(result)
  } else {
    printReport(result)
  }

  const hasCritical = result.findings.some((f) => f.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
}
