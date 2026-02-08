import { Finding, Severity, AIFinding } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

export interface AIProvider {
  name: string;
  analyze(code: string, context: string): Promise<AIFinding[]>;
  isAvailable(): boolean;
}

const SUSPICIOUS_PATTERNS = [
  { pattern: /(?:setTimeout|setInterval)\s*\(\s*\w+\s*,\s*0\s*\)/, reason: 'Potential race condition with zero-delay timer' },
  { pattern: /(?:await|async).*(?:parallel|all|race).*(?:db|database|write|update|delete|remove)/i, reason: 'Concurrent database operations may cause race conditions' },
  { pattern: /if\s*\(\s*!?\s*(?:req|request)\.(?:user|session|auth)\s*\)\s*\{?\s*(?:return|throw|next)?[^}]*\}?\s*(?:\/\/|$)/i, reason: 'Authentication check may have bypass logic' },
  { pattern: /(?:try\s*\{[^}]*(?:throw|error|reject)[^}]*\}\s*catch\s*\(\s*\w+\s*\)\s*\{[^}]*\})/i, reason: 'Error handling may silently swallow security exceptions' },
  { pattern: /(?:\.then\s*\([^)]*\)\s*\.catch\s*\(\s*(?:\(\s*\)\s*=>|function\s*\(\s*\))\s*\{?\s*\}?\s*\))/i, reason: 'Empty catch handler silences errors' },
  { pattern: /(?:Object\.keys|for\s*\(\s*(?:let|var|const)\s+\w+\s+(?:in|of)\s+).*(?:req\.|request\.|body|query|params)/i, reason: 'Iterating over user input keys without validation' },
  { pattern: /(?:async\s+function|=>\s*\{)(?:(?!(?:try|catch|finally)).)*(?:await\s+)(?:(?!(?:try|catch|finally)).)*$/im, reason: 'Async function without error handling' },
  { pattern: /(?:password|secret|token|key).*(?:===?|!==?|==).*(?:undefined|null|''|"")/i, reason: 'Null/empty check on credential may allow bypass' },
];

export function detectSuspiciousPatterns(content: string, filePath: string, language: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const { pattern, reason } of SUSPICIOUS_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        findings.push({
          id: `ZDAY-PATTERN-${filePath}:${i + 1}`,
          ruleId: 'ZDAY-SUSPICIOUS',
          title: 'Suspicious Pattern (AI Analysis Recommended)',
          description: reason,
          severity: Severity.LOW,
          confidence: 'low',
          filePath, line: i + 1,
          codeSnippet: getSnippet(lines, i),
          cwe: 'CWE-691',
          remediation: 'Enable AI analysis (--ai) for deeper investigation of this pattern.',
          fingerprint: generateFingerprint('ZDAY', filePath, lines[i].trim()),
        });
      }
    }
  }

  return findings;
}

export async function analyzeWithAI(
  code: string,
  filePath: string,
  language: string,
  provider: AIProvider
): Promise<Finding[]> {
  if (!provider.isAvailable()) return [];

  try {
    const context = `File: ${filePath}\nLanguage: ${language}\n\nAnalyze this code for security vulnerabilities including:\n- Logic bugs that could lead to authorization bypass\n- Race conditions in concurrent operations\n- Business logic vulnerabilities\n- Novel attack vectors not caught by pattern matching\n- Time-of-check-to-time-of-use (TOCTOU) issues\n- Integer overflow/underflow\n- Null pointer dereference\n- Information leakage`;

    const aiFindings = await provider.analyze(code, context);

    return aiFindings.map((af, index) => ({
      id: `ZDAY-AI-${filePath}:${index}`,
      ruleId: 'ZDAY-AI',
      title: af.title,
      description: af.description,
      severity: af.severity,
      confidence: af.confidence,
      filePath,
      line: af.line || 1,
      codeSnippet: code.split('\n').slice(
        Math.max(0, (af.line || 1) - 3),
        (af.line || 1) + 2
      ).join('\n'),
      cwe: af.cwe,
      owasp: 'A04',
      remediation: af.remediation,
      aiEnhanced: true,
      fingerprint: generateFingerprint('ZDAY-AI', filePath, af.title),
    }));
  } catch {
    return [];
  }
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
