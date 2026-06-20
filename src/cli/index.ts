#!/usr/bin/env node

import { writeFile } from 'fs/promises'
import { parseArgs } from './args.js'
import { scan } from '../scanner/index.js'
import { scanHistory } from '../scanner/history.js'
import { scanStaged } from '../scanner/staged.js'
import { loadIgnoreFile } from '../scanner/ignorefile.js'
import { installHook } from '../install-hook.js'
import { loadBaseline, filterBaseline, writeBaseline } from '../baseline.js'
import { printReport, printHistoryReport } from '../reporter/terminal.js'
import { printJson, printHistoryJson } from '../reporter/json.js'
import { generateHtml } from '../reporter/html.js'
import { generateSarif } from '../reporter/sarif.js'

const args = parseArgs(process.argv)

if (args.help) {
  console.log(`
secretguard — scan source code for secrets, credentials, and PII

Usage:
  secretguard [path] [options]
  secretguard install-hook [path]

Options:
  --ignore, -i <path>       Ignore a path (repeatable)
  --json                    Output results as JSON
  --history                 Scan full git commit history
  --staged                  Scan only staged (pre-commit) changes
  --sarif <file>            Save SARIF report (for GitHub Code Scanning)
  --baseline <file>         Ignore findings present in baseline file
  --update-baseline <file>  Write current findings as new baseline
  --output, -o <file>       Save HTML report to file
  --help, -h                Show this help message

Examples:
  secretguard .
  secretguard ./src --ignore tests
  secretguard . --json
  secretguard . --history
  secretguard . --staged
  secretguard install-hook
  secretguard . --sarif results.sarif
  secretguard . --baseline .secretguard-baseline.json
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
  const rawResult = await scan(args.target, { ignore: [...args.ignore, ...fileIgnore] })

  let findings = rawResult.findings

  if (args.baseline) {
    const baseline = await loadBaseline(args.baseline)
    findings = filterBaseline(findings, baseline)
  }

  if (args.updateBaseline && args.baseline) {
    await writeBaseline(args.baseline, rawResult.findings)
    console.log(`Baseline written to ${args.baseline}`)
  }

  const result = { ...rawResult, findings }

  if (args.output) {
    const html = generateHtml(result)
    await writeFile(args.output, html, 'utf-8')
    console.log(`HTML report saved to ${args.output}`)
  }

  if (args.sarif) {
    const sarif = generateSarif(result)
    await writeFile(args.sarif, sarif, 'utf-8')
    console.log(`SARIF report saved to ${args.sarif}`)
  }

  if (args.json) {
    printJson(result)
  } else {
    printReport(result)
  }

  const hasCritical = result.findings.some((f) => f.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
}
