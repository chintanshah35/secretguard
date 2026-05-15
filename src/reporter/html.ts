import type { ScanResult } from '../patterns/types.js'

// TODO: styles, severity colors, full findings table
export function generateHtml(result: ScanResult): string {
  return `<!DOCTYPE html>
<html>
<head><title>secretscan report</title></head>
<body>
<h1>secretscan</h1>
<p>Scanned ${result.scanned} files, found ${result.findings.length} issues</p>
</body>
</html>`
}
