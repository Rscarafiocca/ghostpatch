import * as path from 'path';
import { Finding, ScanResult, Severity, SEVERITY_COLORS, SEVERITY_ICONS } from './severity';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const WHITE = '\x1b[37m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';

// ============================================================
// Terminal Reporter
// ============================================================
export function reportTerminal(result: ScanResult, quiet: boolean = false): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}${WHITE}  GhostPatch Security Scan Report${RESET}`);
  lines.push(`${DIM}  ${'='.repeat(50)}${RESET}`);
  lines.push('');

  // Summary
  lines.push(`  ${DIM}Target:${RESET}  ${result.target}`);
  lines.push(`  ${DIM}Files:${RESET}   ${result.filesScanned} scanned, ${result.filesSkipped} skipped`);
  lines.push(`  ${DIM}Time:${RESET}    ${result.durationMs}ms`);
  lines.push(`  ${DIM}AI:${RESET}      ${result.aiEnabled ? 'enabled' : 'disabled'}`);
  lines.push('');

  // Severity breakdown
  const { bySeverity } = result.summary;
  const critCount = bySeverity[Severity.CRITICAL] || 0;
  const highCount = bySeverity[Severity.HIGH] || 0;
  const medCount = bySeverity[Severity.MEDIUM] || 0;
  const lowCount = bySeverity[Severity.LOW] || 0;
  const infoCount = bySeverity[Severity.INFO] || 0;

  lines.push(`  ${SEVERITY_COLORS[Severity.CRITICAL]} CRITICAL ${RESET} ${critCount}`);
  lines.push(`  ${SEVERITY_COLORS[Severity.HIGH]} HIGH ${RESET}     ${highCount}`);
  lines.push(`  ${SEVERITY_COLORS[Severity.MEDIUM]} MEDIUM ${RESET}   ${medCount}`);
  lines.push(`  ${SEVERITY_COLORS[Severity.LOW]} LOW ${RESET}      ${lowCount}`);
  lines.push(`  ${DIM} INFO ${RESET}     ${infoCount}`);
  lines.push('');

  if (result.summary.total === 0) {
    lines.push(`  ${GREEN}${BOLD}No security issues found!${RESET}`);
    lines.push('');
    return lines.join('\n');
  }

  lines.push(`  ${DIM}${'─'.repeat(60)}${RESET}`);
  lines.push('');

  if (quiet) {
    for (const finding of result.findings) {
      const icon = SEVERITY_ICONS[finding.severity];
      const color = SEVERITY_COLORS[finding.severity];
      const relPath = path.relative(result.target, finding.filePath) || finding.filePath;
      lines.push(`  ${color}${icon}${RESET} ${finding.title} ${DIM}${relPath}:${finding.line}${RESET}`);
    }
  } else {
    for (const finding of result.findings) {
      lines.push(formatFinding(finding, result.target));
    }
  }

  lines.push('');
  lines.push(`  ${DIM}${'─'.repeat(60)}${RESET}`);
  lines.push(`  ${BOLD}Total: ${result.summary.total} issue(s) found${RESET}`);

  if (critCount > 0) {
    lines.push(`  ${RED}${BOLD}${critCount} critical issue(s) require immediate attention!${RESET}`);
  }

  lines.push('');
  return lines.join('\n');
}

function formatFinding(finding: Finding, basePath: string): string {
  const lines: string[] = [];
  const color = SEVERITY_COLORS[finding.severity];
  const icon = SEVERITY_ICONS[finding.severity];
  const relPath = path.relative(basePath, finding.filePath) || finding.filePath;

  lines.push(`  ${color}${BOLD}${icon} ${finding.title}${RESET}`);
  lines.push(`  ${DIM}${relPath}:${finding.line}${RESET}${finding.cwe ? `  ${DIM}${finding.cwe}${RESET}` : ''}${finding.aiEnhanced ? `  ${CYAN}[AI]${RESET}` : ''}`);
  lines.push(`  ${finding.description}`);
  lines.push('');

  if (finding.codeSnippet) {
    const snippetLines = finding.codeSnippet.split('\n');
    for (const sl of snippetLines) {
      if (sl.startsWith('>')) {
        lines.push(`  ${color}${sl}${RESET}`);
      } else {
        lines.push(`  ${DIM}${sl}${RESET}`);
      }
    }
    lines.push('');
  }

  if (finding.remediation) {
    lines.push(`  ${GREEN}Fix: ${finding.remediation}${RESET}`);
  }

  lines.push(`  ${DIM}${'─'.repeat(60)}${RESET}`);
  lines.push('');

  return lines.join('\n');
}

// ============================================================
// JSON Reporter
// ============================================================
export function reportJSON(result: ScanResult): string {
  return JSON.stringify({
    ghostpatch: {
      version: '1.0.0',
      scanDate: result.startTime.toISOString(),
    },
    target: result.target,
    duration: result.durationMs,
    filesScanned: result.filesScanned,
    filesSkipped: result.filesSkipped,
    aiEnabled: result.aiEnabled,
    summary: result.summary,
    findings: result.findings.map(f => ({
      id: f.id,
      ruleId: f.ruleId,
      title: f.title,
      description: f.description,
      severity: f.severity,
      confidence: f.confidence,
      location: {
        file: f.filePath,
        line: f.line,
        column: f.column,
        endLine: f.endLine,
        endColumn: f.endColumn,
      },
      cwe: f.cwe,
      owasp: f.owasp,
      codeSnippet: f.codeSnippet,
      remediation: f.remediation,
      aiEnhanced: f.aiEnhanced || false,
      fingerprint: f.fingerprint,
    })),
  }, null, 2);
}

// ============================================================
// SARIF Reporter (Static Analysis Results Interchange Format)
// ============================================================
export function reportSARIF(result: ScanResult): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'GhostPatch',
          version: '1.0.0',
          informationUri: 'https://github.com/ghostpatch/ghostpatch',
          rules: getUniqueRules(result.findings),
        },
      },
      results: result.findings.map(f => ({
        ruleId: f.ruleId,
        level: sarifLevel(f.severity),
        message: {
          text: f.description,
        },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: f.filePath.replace(/\\/g, '/'),
            },
            region: {
              startLine: f.line,
              startColumn: f.column || 1,
              endLine: f.endLine || f.line,
              endColumn: f.endColumn,
            },
          },
        }],
        fingerprints: {
          'ghostpatch/v1': f.fingerprint,
        },
        fixes: f.remediation ? [{
          description: { text: f.remediation },
        }] : undefined,
      })),
    }],
  };

  return JSON.stringify(sarif, null, 2);
}

function sarifLevel(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
    case Severity.HIGH: return 'error';
    case Severity.MEDIUM: return 'warning';
    case Severity.LOW:
    case Severity.INFO: return 'note';
  }
}

function getUniqueRules(findings: Finding[]) {
  const seen = new Set<string>();
  const rules: any[] = [];

  for (const f of findings) {
    if (!seen.has(f.ruleId)) {
      seen.add(f.ruleId);
      rules.push({
        id: f.ruleId,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        help: { text: f.remediation || '' },
        properties: {
          cwe: f.cwe,
          owasp: f.owasp,
        },
      });
    }
  }

  return rules;
}

// ============================================================
// HTML Reporter
// ============================================================
export function reportHTML(result: ScanResult): string {
  const { bySeverity } = result.summary;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GhostPatch Security Report</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
h1 { color: #f0f6fc; font-size: 2rem; margin-bottom: 0.5rem; }
.subtitle { color: #8b949e; margin-bottom: 2rem; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; text-align: center; }
.stat-value { font-size: 2rem; font-weight: bold; }
.stat-label { color: #8b949e; font-size: 0.85rem; text-transform: uppercase; }
.critical .stat-value { color: #f85149; }
.high .stat-value { color: #f0883e; }
.medium .stat-value { color: #d29922; }
.low .stat-value { color: #3fb950; }
.info .stat-value { color: #58a6ff; }
.finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
.finding-title { font-size: 1.1rem; font-weight: 600; color: #f0f6fc; }
.badge { padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
.badge-critical { background: #f85149; color: #fff; }
.badge-high { background: #f0883e; color: #fff; }
.badge-medium { background: #d29922; color: #000; }
.badge-low { background: #3fb950; color: #000; }
.badge-info { background: #58a6ff; color: #000; }
.finding-meta { color: #8b949e; font-size: 0.85rem; margin-bottom: 0.5rem; }
.finding-desc { margin-bottom: 1rem; }
pre { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.85rem; }
.fix { color: #3fb950; background: #0d2818; border: 1px solid #238636; border-radius: 6px; padding: 0.75rem; margin-top: 0.5rem; font-size: 0.9rem; }
.chart { display: flex; height: 24px; border-radius: 12px; overflow: hidden; margin-bottom: 2rem; }
.chart-seg { transition: width 0.3s; }
.chart-critical { background: #f85149; }
.chart-high { background: #f0883e; }
.chart-medium { background: #d29922; }
.chart-low { background: #3fb950; }
.chart-info { background: #58a6ff; }
.footer { text-align: center; color: #8b949e; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #30363d; }
.ai-badge { background: #a371f7; color: #fff; padding: 0.1rem 0.4rem; border-radius: 8px; font-size: 0.7rem; margin-left: 0.5rem; }
</style>
</head>
<body>
<div class="container">
<h1>GhostPatch Security Report</h1>
<p class="subtitle">Scan completed ${result.startTime.toISOString()} | ${result.filesScanned} files scanned | ${result.durationMs}ms</p>

${result.summary.total > 0 ? `<div class="chart">
${chartSegment('critical', bySeverity[Severity.CRITICAL], result.summary.total)}
${chartSegment('high', bySeverity[Severity.HIGH], result.summary.total)}
${chartSegment('medium', bySeverity[Severity.MEDIUM], result.summary.total)}
${chartSegment('low', bySeverity[Severity.LOW], result.summary.total)}
${chartSegment('info', bySeverity[Severity.INFO], result.summary.total)}
</div>` : ''}

<div class="summary">
<div class="stat critical"><div class="stat-value">${bySeverity[Severity.CRITICAL] || 0}</div><div class="stat-label">Critical</div></div>
<div class="stat high"><div class="stat-value">${bySeverity[Severity.HIGH] || 0}</div><div class="stat-label">High</div></div>
<div class="stat medium"><div class="stat-value">${bySeverity[Severity.MEDIUM] || 0}</div><div class="stat-label">Medium</div></div>
<div class="stat low"><div class="stat-value">${bySeverity[Severity.LOW] || 0}</div><div class="stat-label">Low</div></div>
<div class="stat info"><div class="stat-value">${bySeverity[Severity.INFO] || 0}</div><div class="stat-label">Info</div></div>
</div>

${result.findings.length === 0 ? '<div class="finding"><p style="text-align:center; color:#3fb950; font-size:1.2rem;">No security issues found!</p></div>' : ''}

${result.findings.map(f => `<div class="finding">
<div class="finding-header">
<span class="finding-title">${escapeHtml(f.title)}${f.aiEnhanced ? '<span class="ai-badge">AI</span>' : ''}</span>
<span class="badge badge-${f.severity}">${f.severity}</span>
</div>
<div class="finding-meta">${escapeHtml(path.relative(result.target, f.filePath) || f.filePath)}:${f.line}${f.cwe ? ` | ${f.cwe}` : ''}${f.owasp ? ` | OWASP ${f.owasp}` : ''}</div>
<div class="finding-desc">${escapeHtml(f.description)}</div>
${f.codeSnippet ? `<pre><code>${escapeHtml(f.codeSnippet)}</code></pre>` : ''}
${f.remediation ? `<div class="fix">Fix: ${escapeHtml(f.remediation)}</div>` : ''}
</div>`).join('\n')}

<div class="footer">
Generated by GhostPatch v1.0.0 | AI-Powered Security Scanner
</div>
</div>
</body>
</html>`;
}

function chartSegment(severity: string, count: number, total: number): string {
  if (!count || total === 0) return '';
  const pct = (count / total) * 100;
  return `<div class="chart-seg chart-${severity}" style="width:${pct}%" title="${severity}: ${count}"></div>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================================
// Report dispatcher
// ============================================================
export function generateReport(
  result: ScanResult,
  format: 'terminal' | 'json' | 'sarif' | 'html' = 'terminal',
  quiet: boolean = false,
): string {
  switch (format) {
    case 'json': return reportJSON(result);
    case 'sarif': return reportSARIF(result);
    case 'html': return reportHTML(result);
    case 'terminal':
    default: return reportTerminal(result, quiet);
  }
}
