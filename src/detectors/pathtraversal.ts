import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'PATH-TRAVERSAL-FS', name: 'Path Traversal (File System)', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-22',
    pattern: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|unlink|unlinkSync|open|openSync|access|accessSync)\s*\(\s*(?:req\.|request\.|input|user|param|query|body|path\.join\s*\([^)]*req)/i,
    description: 'File operation with user-controlled path — directory traversal risk.',
    remediation: 'Validate paths. Use path.resolve() and verify against a base directory.',
  },
  {
    id: 'PATH-TRAVERSAL-PY', name: 'Path Traversal (Python)', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-22',
    pattern: /(?:open|os\.path\.join|pathlib\.Path|shutil\.copy|os\.rename)\s*\(\s*(?:request\.|input|user_|flask\.request|args\.get|form\.get)/i,
    description: 'File operation with user-controlled path in Python.',
    remediation: 'Use os.path.realpath() and verify against base directory.',
  },
  {
    id: 'PATH-TRAVERSAL-JAVA', name: 'Path Traversal (Java)', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-22',
    pattern: /(?:new\s+File|Paths\.get|FileInputStream|FileOutputStream)\s*\(\s*(?:request\.getParameter|servletRequest|param|input)/i,
    description: 'File operation with user-controlled path in Java.',
    remediation: 'Canonicalize path and verify it starts with the expected base directory.',
  },
  {
    id: 'PATH-ZIP-SLIP', name: 'Zip Slip Vulnerability', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-22',
    pattern: /(?:extractAll|extract\s*\(|unzip|ZipFile|tar\.extractall|tar\.extract|decompress|gunzip)\s*\(/i,
    antiPattern: /(?:validatePath|sanitize|startsWith|normalize|realpath|abspath|canonical)/i,
    description: 'Archive extraction without path validation — Zip Slip vulnerability.',
    remediation: 'Validate extracted paths stay within intended directory.',
  },
  {
    id: 'PATH-DOT-DOT', name: 'Directory Traversal Sequence', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-22',
    pattern: /(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c)/i,
    antiPattern: /(?:import|require|from\s+['"]|test|spec|relative)/,
    description: 'Directory traversal sequence detected.',
    remediation: 'Reject input containing ".." path sequences.',
  },
  {
    id: 'PATH-SEND-FILE', name: 'Unsafe File Serving', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-22',
    pattern: /(?:sendFile|send_file|download|serveFile)\s*\(\s*(?:req\.|request\.|path\.join\s*\([^)]*(?:req|param|query))/i,
    description: 'File sent to client based on user input.',
    remediation: 'Validate file paths and restrict to safe directories.',
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
          cwe: pat.cwe, owasp: 'A01',
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
  return lines.slice(start, end)
    .map((l, i) => {
      const lineNum = start + i + 1;
      const marker = (start + i === index) ? '>' : ' ';
      return `${marker} ${lineNum} | ${l}`;
    }).join('\n');
}
