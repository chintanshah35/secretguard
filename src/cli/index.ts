#!/usr/bin/env node

const args = process.argv.slice(2)

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
secretscan — scan source code for secrets, credentials, and PII

Usage:
  secretscan [path] [options]

Options:
  --ignore <path>   Ignore a path (can be used multiple times)
  --json            Output results as JSON
  --output <file>   Save HTML report to file
  --help            Show this help message
  `)
  process.exit(0)
}

console.log('secretscan wip')
