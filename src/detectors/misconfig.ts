import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'CFG-DEBUG-ON', name: 'Debug Mode Enabled', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-489',
    pattern: /(?:app\.debug\s*=\s*True|DEBUG\s*=\s*True|debug\s*:\s*true|EnableDebugging|\.setDebug\(true\))/i,
    antiPattern: /(?:process\.env|os\.environ|config\.get|if\s|\.env|test|spec)/,
    description: 'Debug mode hardcoded as enabled.',
    remediation: 'Use environment variable for debug mode.',
  },
  {
    id: 'CFG-INSECURE-COOKIE', name: 'Insecure Cookie Configuration', severity: Severity.MEDIUM, confidence: 'high' as const,
    cwe: 'CWE-614',
    pattern: /(?:secure\s*:\s*false|httpOnly\s*:\s*false)/i,
    description: 'Cookie configured with insecure flags.',
    remediation: 'Set secure: true and httpOnly: true for session cookies.',
  },
  {
    id: 'CFG-SAMESITE-NONE', name: 'SameSite None Cookie', severity: Severity.MEDIUM, confidence: 'high' as const,
    cwe: 'CWE-1275',
    pattern: /sameSite\s*:\s*['"]?none['"]?/i,
    description: 'Cookie SameSite set to None allows cross-site requests.',
    remediation: 'Use SameSite: "strict" or "lax" unless cross-site is required.',
  },
  {
    id: 'CFG-MISSING-HELMET', name: 'Missing Security Headers', severity: Severity.LOW, confidence: 'low' as const,
    cwe: 'CWE-693',
    pattern: /(?:app\.listen|createServer|express\(\))/,
    antiPattern: /(?:helmet|security.*header|Content-Security-Policy|X-Frame-Options|Strict-Transport|csp)/i,
    description: 'Web server may lack security headers.',
    remediation: 'Use Helmet.js or manually set CSP, HSTS, X-Frame-Options.',
  },
  {
    id: 'CFG-CORS-STAR', name: 'CORS Wildcard Origin', severity: Severity.MEDIUM, confidence: 'high' as const,
    cwe: 'CWE-942',
    pattern: /(?:origin\s*:\s*(?:true|['"]?\*['"]?)|Access-Control-Allow-Origin.*\*)/,
    description: 'CORS allows all origins.',
    remediation: 'Restrict CORS to specific trusted origins.',
  },
  {
    id: 'CFG-GRAPHQL-INTRO', name: 'GraphQL Introspection Enabled', severity: Severity.MEDIUM, confidence: 'high' as const,
    cwe: 'CWE-200',
    pattern: /introspection\s*:\s*true/,
    description: 'GraphQL introspection enabled — schema exposed.',
    remediation: 'Disable introspection in production.',
  },
  {
    id: 'CFG-ROOT-STATIC', name: 'Static Files from Root', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-538',
    pattern: /(?:express\.static|serveStatic)\s*\(\s*['"]\.?\/?['"]\s*\)/,
    description: 'Serving static files from root may expose sensitive files.',
    remediation: 'Serve static files from a dedicated public/ directory.',
  },
  {
    id: 'CFG-DEFAULT-PORT', name: 'Default Debug Port', severity: Severity.LOW, confidence: 'medium' as const,
    cwe: 'CWE-489',
    pattern: /(?:--inspect|--debug|debugger.*port|debug-port)\s*(?:=\s*)?\d+/,
    description: 'Debug port configuration found.',
    remediation: 'Ensure debug ports are not exposed in production.',
  },
  {
    id: 'CFG-PERMISSIVE-PERMS', name: 'Permissive File Permissions', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-732',
    pattern: /(?:chmod\s+(?:777|666)|0o?777|permissions?\s*[:=]\s*0o?777)/,
    description: 'World-writable file permissions.',
    remediation: 'Use restrictive permissions (644 for files, 755 for directories).',
  },
  {
    id: 'CFG-BIND-ALL', name: 'Binding to All Interfaces', severity: Severity.LOW, confidence: 'medium' as const,
    cwe: 'CWE-668',
    pattern: /(?:listen\s*\([^)]*['"]0\.0\.0\.0['"]|host\s*[:=]\s*['"]0\.0\.0\.0['"]|INADDR_ANY)/,
    description: 'Server binding to all network interfaces.',
    remediation: 'Bind to 127.0.0.1 in development.',
  },
  {
    id: 'CFG-STACK-TRACE', name: 'Stack Trace Exposure', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-209',
    pattern: /(?:res\.(?:send|json)\s*\(.*(?:err\.stack|error\.stack|stackTrace)|showStackError\s*:\s*true)/i,
    description: 'Stack traces may be sent to clients.',
    remediation: 'Log errors server-side, send generic messages to clients.',
  },
  {
    id: 'CFG-BODY-NO-LIMIT', name: 'Body Parser Without Size Limit', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-400',
    pattern: /(?:bodyParser\.json\(\s*\)|express\.json\(\s*\))/,
    antiPattern: /limit/,
    description: 'JSON body parser without size limit.',
    remediation: 'Set a body size limit: express.json({ limit: "100kb" }).',
  },
  {
    id: 'CFG-ENV-EXPOSURE', name: 'Environment Variables Exposed', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-200',
    pattern: /(?:res\.(?:send|json)|response\.)\s*\(\s*process\.env\s*\)/,
    description: 'Entire process.env sent to client.',
    remediation: 'Only send specific, non-sensitive config values.',
  },
  {
    id: 'CFG-ELECTRON-NODE', name: 'Electron nodeIntegration Enabled', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-94',
    pattern: /nodeIntegration\s*:\s*true/,
    description: 'Electron nodeIntegration enabled — XSS leads to RCE.',
    remediation: 'Disable nodeIntegration and use contextBridge.',
  },
  {
    id: 'CFG-ELECTRON-CTX', name: 'Electron contextIsolation Disabled', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-94',
    pattern: /contextIsolation\s*:\s*false/,
    description: 'Electron contextIsolation disabled.',
    remediation: 'Enable contextIsolation.',
  },
];

export function detect(content: string, filePath: string, language: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const pat of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pat.pattern.test(line)) {
        if (pat.antiPattern) {
          const cs = Math.max(0, i - 3);
          const ce = Math.min(lines.length, i + 4);
          if (pat.antiPattern.test(lines.slice(cs, ce).join('\n'))) continue;
        }
        findings.push({
          id: `${pat.id}-${filePath}:${i + 1}`,
          ruleId: pat.id, title: pat.name, description: pat.description,
          severity: pat.severity, confidence: pat.confidence,
          filePath, line: i + 1,
          codeSnippet: getSnippet(lines, i),
          cwe: pat.cwe, owasp: 'A05',
          remediation: pat.remediation,
          fingerprint: generateFingerprint(pat.id, filePath, line.trim()),
        });
      }
    }
  }
  return findings;
}

function getSnippet(lines: string[], index: number, context = 2): string {
  const start = Math.max(0, index - context);
  const end = Math.min(lines.length, index + context + 1);
  return lines.slice(start, end).map((l, i) => {
    const lineNum = start + i + 1;
    const marker = (start + i === index) ? '>' : ' ';
    return `${marker} ${lineNum} | ${l}`;
  }).join('\n');
}
