#!/usr/bin/env node

import { writeFile } from 'fs/promises'
import { parseArgs } from './args.js'
import { scan } from '../scanner/index.js'
import { scanHistory } from '../scanner/history.js'
import { scanStaged } from '../scanner/staged.js'
import { loadIgnoreFile } from '../scanner/ignorefile.js'
import { installHook } from '../install-hook.js'
import { printReport, printHistoryReport } from '../reporter/terminal.js'
import { printJson, printHistoryJson } from '../reporter/json.js'
import { generateHtml } from '../reporter/html.js'

const args = parseArgs(process.argv)

if (args.help) {
  console.log(`
secretguard — scan source code for secrets, credentials, and PII

Usage:
  secretguard [path] [options]
  secretguard install-hook [path]

Options:
  --ignore, -i <path>   Ignore a path (repeatable)
  --json                Output results as JSON
  --history             Scan full git commit history
  --staged              Scan only staged (pre-commit) changes
  --output, -o <file>   Save HTML report to file
  --help, -h            Show this help message

Examples:
  secretguard .
  secretguard ./src --ignore tests
  secretguard . --json
  secretguard . --history
  secretguard . --staged
  secretguard install-hook
  secretguard . --output report.html
  `)
  process.exit(0)
}

if (args.installHook) {
  try {
    await installHook(args.target)
    console.log(`pre-commit hook installed at ${args.target}/.git/hooks/pre-commit`)
  } catch (error) {
    console.error(String(error))
    process.exit(1)
  }
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
} else if (args.staged) {
  const result = await scanStaged(args.target)

  if (args.json) {
    printJson(result)
  } else {
    printReport(result)
  }

  const hasCritical = result.findings.some((f) => f.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
} else {
  const fileIgnore = await loadIgnoreFile(args.target)
  const result = await scan(args.target, { ignore: [...args.ignore, ...fileIgnore] })

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
