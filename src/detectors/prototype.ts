import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'PROTO-MERGE', name: 'Prototype Pollution via Deep Merge', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-1321',
    pattern: /(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|deepmerge|deep-extend|merge-deep|lodash\.merge)\s*\(/,
    antiPattern: /(?:Object\.create\(null\)|hasOwnProperty|__proto__|prototype|constructor.*check)/i,
    description: 'Deep merge may allow prototype pollution.',
    remediation: 'Validate input keys. Reject __proto__, constructor, and prototype.',
  },
  {
    id: 'PROTO-BRACKET', name: 'Dynamic Property Assignment', severity: Severity.MEDIUM, confidence: 'low' as const,
    cwe: 'CWE-1321',
    pattern: /\w+\s*\[\s*(?:key|prop|name|field|attr|k|p|property)\s*\]\s*=\s*(?!undefined|null|false|true|0|''|"")/,
    antiPattern: /(?:hasOwnProperty|Object\.keys|Object\.entries|whitelist|allowlist|sanitize|__proto__|prototype|constructor)/i,
    description: 'Dynamic property assignment without prototype pollution guard.',
    remediation: 'Check key is not __proto__, constructor, or prototype before assignment.',
  },
  {
    id: 'PROTO-JSON-PARSE', name: 'JSON.parse Without Prototype Check', severity: Severity.LOW, confidence: 'low' as const,
    cwe: 'CWE-1321',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|request\.|body|input|user|data)/i,
    antiPattern: /(?:reviver|filter|sanitize|validate|schema)/i,
    description: 'JSON.parse of user input may contain __proto__ keys.',
    remediation: 'Use a JSON reviver to strip __proto__ keys, or validate input schema.',
  },
  {
    id: 'PROTO-RECURSIVE', name: 'Recursive Object Copy', severity: Severity.MEDIUM, confidence: 'low' as const,
    cwe: 'CWE-1321',
    pattern: /function\s+(?:deep[Cc]opy|deep[Cc]lone|deep[Mm]erge|extend|assign[Dd]eep)\s*\(/,
    antiPattern: /(?:__proto__|prototype|constructor|hasOwnProperty|Object\.create\(null\))/i,
    description: 'Custom deep copy/merge may be vulnerable to prototype pollution.',
    remediation: 'Add checks for __proto__, constructor, and prototype in recursive operations.',
  },
];

export function detect(content: string, filePath: string, language: string): Finding[] {
  const findings: Finding[] = [];
  if (!['javascript', 'typescript'].includes(language)) return findings;

  const lines = content.split('\n');
  for (const pat of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pat.pattern.test(line)) {
        if (pat.antiPattern) {
          const cs = Math.max(0, i - 5);
          const ce = Math.min(lines.length, i + 6);
          if (pat.antiPattern.test(lines.slice(cs, ce).join('\n'))) continue;
        }
        findings.push({
          id: `${pat.id}-${filePath}:${i + 1}`,
          ruleId: pat.id, title: pat.name, description: pat.description,
          severity: pat.severity, confidence: pat.confidence,
          filePath, line: i + 1,
          codeSnippet: getSnippet(lines, i),
          cwe: pat.cwe, owasp: 'A03',
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
