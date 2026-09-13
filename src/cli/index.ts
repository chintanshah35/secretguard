#!/usr/bin/env node

import { writeFile } from 'fs/promises'
import { parseArgs } from './args.js'
import { scan } from '../scanner/index.js'
import { scanHistory } from '../scanner/history.js'
import { scanStaged } from '../scanner/staged.js'
import { loadIgnoreFile } from '../scanner/ignorefile.js'
import { installHook } from '../install-hook.js'
import { loadBaseline, filterBaseline, writeBaseline } from '../baseline.js'
import { withRemediation } from '../enrich.js'
import { verifyFindings } from '../verify.js'
import { withoutRaw } from '../sanitize.js'
import { printReport, printHistoryReport } from '../reporter/terminal.js'
import { printJson, printHistoryJson } from '../reporter/json.js'
import { generateHtml } from '../reporter/html.js'
import { generateSarif } from '../reporter/sarif.js'
import type { Finding, ScanResult } from '../patterns/types.js'

const VERIFY_WARNING = `WARNING: --verify sends detected credential values to provider APIs
(OpenAI, Anthropic, GitHub, Stripe, AWS STS) to check whether they are active.
Source files are not uploaded. Do not use --verify if this violates your
organization's security policy.`

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
  --verify                  Live-check keys (sends candidate secrets to providers)
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
  secretguard . --verify
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

async function finalizeFindings(findings: Finding[]) {
  let next = withRemediation(findings)
  if (args.verify) {
    console.error(VERIFY_WARNING)
    console.error('')
    next = await verifyFindings(next)
  }
  // Drop raw values before any reporter output
  return withoutRaw(next)
}

if (args.history) {
  if (args.verify) {
    console.error('secretguard: --verify is not supported with --history yet (raw values are not kept)')
  }

  const result = await scanHistory(args.target)

  if (args.json) {
    printHistoryJson(result)
  } else {
    printHistoryReport(result)
  }

  const hasCritical = result.findings.some((finding) => finding.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
} else if (args.staged) {
  // Keep raw until after optional --verify, then strip in finalizeFindings
  const result = await scanStaged(args.target, { includeRaw: true })
  const findings = await finalizeFindings(result.findings)
  const enriched: ScanResult = { ...result, findings }

  if (args.json) {
    printJson(enriched)
  } else {
    printReport(enriched)
  }

  const hasCritical = findings.some((finding) => finding.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
} else {
  const fileIgnore = await loadIgnoreFile(args.target)
  const rawResult = await scan(args.target, {
    ignore: [...args.ignore, ...fileIgnore],
    includeRaw: true,
  })

  let findings = rawResult.findings

  if (args.baseline) {
    const baseline = await loadBaseline(args.baseline)
    findings = filterBaseline(findings, baseline)
  }

  if (args.updateBaseline && args.baseline) {
    await writeBaseline(args.baseline, withoutRaw(rawResult.findings))
    console.log(`Baseline written to ${args.baseline}`)
  }

  findings = await finalizeFindings(findings)
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

  const hasCritical = findings.some((finding) => finding.severity === 'CRITICAL')
  process.exit(hasCritical ? 1 : 0)
}
