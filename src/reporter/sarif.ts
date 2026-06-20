import type { ScanResult, Finding } from '../patterns/types.js'

type SarifLevel = 'error' | 'warning' | 'note' | 'none'

function toSarifLevel(severity: Finding['severity']): SarifLevel {
  switch (severity) {
    case 'CRITICAL': return 'error'
    case 'HIGH': return 'warning'
    case 'MEDIUM': return 'note'
    case 'LOW': return 'none'
  }
}

/**
 * Generates a SARIF 2.1.0 document from a scan result.
 * Compatible with GitHub Code Scanning / Security tab uploads.
 */
export function generateSarif(result: ScanResult, version: string = '0.0.0'): string {
  const ruleIds = [...new Set(result.findings.map((f) => f.pattern))]

  const rules = ruleIds.map((id) => {
    const finding = result.findings.find((f) => f.pattern === id)!
    return {
      id,
      name: id.replace(/\s+/g, ''),
      shortDescription: { text: id },
      defaultConfiguration: {
        level: toSarifLevel(finding.severity),
      },
    }
  })

  const runs = [
    {
      tool: {
        driver: {
          name: 'secretguard',
          version,
          informationUri: 'https://github.com/secretguard/secretguard',
          rules,
        },
      },
      results: result.findings.map((finding) => ({
        ruleId: finding.pattern,
        level: toSarifLevel(finding.severity),
        message: {
          text: `${finding.pattern} detected. Value: ${finding.masked}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: finding.file,
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: finding.line,
                startColumn: finding.column,
              },
            },
          },
        ],
      })),
    },
  ]

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs,
  }

  return JSON.stringify(sarif, null, 2)
}
