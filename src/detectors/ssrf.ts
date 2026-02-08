import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'SSRF-USER-URL', name: 'SSRF via User-Controlled URL', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-918',
    pattern: /(?:fetch|axios|http\.get|https\.get|request|urllib|requests\.(?:get|post|put|delete|head)|HttpClient|http\.NewRequest)\s*\(\s*(?:req\.|request\.|input|user|param|query|body|args)/i,
    description: 'HTTP request URL from user input — SSRF risk.',
    remediation: 'Validate URLs against an allowlist. Block internal/private IP ranges.',
  },
  {
    id: 'SSRF-URL-PARAM', name: 'URL From Query Parameter', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-918',
    pattern: /(?:url|uri|endpoint|target|destination|redirect|callback|webhook)\s*[:=]\s*(?:req\.query|req\.params|request\.args|request\.GET|params\[)/i,
    description: 'URL taken from query parameter.',
    remediation: 'Validate URL scheme, host, and resolved IP. Use allowlist.',
  },
  {
    id: 'SSRF-IMAGE-FETCH', name: 'Image/File Fetch from URL', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-918',
    pattern: /(?:download|fetch|grab|load|import)(?:Image|File|URL|Resource|Content)\s*\(\s*(?:url|uri|src|href|link)/i,
    antiPattern: /(?:allowlist|whitelist|validateUrl|isAllowed|checkUrl|blockPrivate|isExternal)/i,
    description: 'File/image download from variable URL.',
    remediation: 'Validate URL and block internal IP ranges before fetching.',
  },
  {
    id: 'SSRF-WEBHOOK', name: 'Webhook URL from User', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-918',
    pattern: /(?:webhook|callback|notify)(?:Url|URL|_url|Uri|URI)\s*[:=]\s*(?:req\.|request\.|body\.|input|user)/i,
    description: 'Webhook URL from user input — can probe internal services.',
    remediation: 'Validate webhook URLs. Block private IP ranges and localhost.',
  },
];

export function detect(content: string, filePath: string, language: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const backendLangs = ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp', 'kotlin'];

  if (!backendLangs.includes(language)) return findings;

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
          cwe: pat.cwe, owasp: 'A10',
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
