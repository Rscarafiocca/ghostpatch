import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'SEC-AWS-KEY', name: 'AWS Access Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/,
    antiPattern: /(?:example|sample|test|fake|dummy|placeholder|xxx|EXAMPLE)/i,
    description: 'AWS access key ID found.', remediation: 'Rotate key immediately. Use IAM roles or env vars.',
  },
  {
    id: 'SEC-AWS-SECRET', name: 'AWS Secret Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /(?:aws_secret|AWS_SECRET)\w*\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/,
    description: 'AWS secret access key found.', remediation: 'Rotate immediately. Use AWS Secrets Manager.',
  },
  {
    id: 'SEC-GITHUB-TOKEN', name: 'GitHub Token', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    description: 'GitHub personal access token found.', remediation: 'Rotate immediately. Use env vars.',
  },
  {
    id: 'SEC-GOOGLE-KEY', name: 'Google API Key', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /AIza[A-Za-z0-9_\\-]{35}/,
    description: 'Google API key found.', remediation: 'Rotate and restrict key scope. Use env vars.',
  },
  {
    id: 'SEC-SLACK-TOKEN', name: 'Slack Token', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /xox[bpors]-[A-Za-z0-9\-]{10,}/,
    description: 'Slack API token found.', remediation: 'Rotate immediately. Use env vars.',
  },
  {
    id: 'SEC-STRIPE-KEY', name: 'Stripe API Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/,
    description: 'Stripe API key found.', remediation: 'Rotate immediately. Use env vars.',
  },
  {
    id: 'SEC-PRIVATE-KEY', name: 'Private Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-321', pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
    description: 'Private key embedded in source.', remediation: 'Remove from source. Use key management service.',
  },
  {
    id: 'SEC-GENERIC-API-KEY', name: 'Generic API Key', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-798', pattern: /(?:api[-_]?key|apikey|API[-_]?KEY)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/i,
    antiPattern: /(?:example|sample|test|fake|dummy|placeholder|xxx|your_|process\.env|os\.environ|config\.|env\[)/i,
    description: 'Hardcoded API key found.', remediation: 'Store API keys in env vars or secrets manager.',
  },
  {
    id: 'SEC-GENERIC-SECRET', name: 'Generic Secret/Password', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-798', pattern: /(?:secret|token|password|passwd|credentials?)\s*[:=]\s*['"][a-zA-Z0-9!@#$%^&*()\-_+=]{12,}['"]/i,
    antiPattern: /(?:example|sample|test|fake|dummy|placeholder|xxx|your_|process\.env|os\.environ|config\.|env\[|<|TODO|CHANGE|REPLACE|type|interface|const\s+\w+:\s*string)/i,
    description: 'Potential hardcoded secret.', remediation: 'Use env vars or secrets manager.',
  },
  {
    id: 'SEC-DB-CONN-STRING', name: 'Database Connection String', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /['"](?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp):\/\/[^:]+:[^@]+@[^'"]+['"]/i,
    antiPattern: /(?:localhost|127\.0\.0\.1|example\.com|process\.env|os\.environ)/i,
    description: 'Database connection string with credentials.', remediation: 'Use env vars for connection strings.',
  },
  {
    id: 'SEC-SENDGRID', name: 'SendGrid API Key', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/,
    description: 'SendGrid API key found.', remediation: 'Rotate immediately. Use env vars.',
  },
  {
    id: 'SEC-TWILIO', name: 'Twilio Credentials', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-798', pattern: /(?:AC[a-z0-9]{32}|SK[a-z0-9]{32})/,
    description: 'Twilio Account SID or API key found.', remediation: 'Rotate immediately. Use env vars.',
  },
  {
    id: 'SEC-FIREBASE', name: 'Firebase Config Exposed', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-798', pattern: /(?:firebase|FIREBASE).*(?:apiKey|authDomain|databaseURL)\s*[:=]\s*['"]/i,
    description: 'Firebase configuration in source.', remediation: 'Use env vars. Secure with Firebase Security Rules.',
  },
  {
    id: 'SEC-HARDCODED-DB-PASS', name: 'Hardcoded Database Password', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /(?:(?:db|database|mysql|postgres|mongo|redis)[-_.]?(?:password|passwd|pass|pwd))\s*[:=]\s*['"][^'"]{4,}['"]/i,
    antiPattern: /(?:process\.env|os\.environ|config\.|env\[|example|sample|test|your_|placeholder)/i,
    description: 'Database password hardcoded.', remediation: 'Use env vars or secrets manager.',
  },
  {
    id: 'SEC-OPENAI-KEY', name: 'OpenAI API Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /sk-[A-Za-z0-9]{32,}/,
    antiPattern: /(?:example|sample|test|fake|placeholder|xxx)/i,
    description: 'OpenAI API key found.', remediation: 'Rotate immediately. Use env vars.',
  },
  {
    id: 'SEC-ANTHROPIC-KEY', name: 'Anthropic API Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-798', pattern: /sk-ant-[A-Za-z0-9\-]{32,}/,
    description: 'Anthropic API key found.', remediation: 'Rotate immediately. Use env vars.',
  },
];

// All languages — secrets can appear anywhere
const ALL_LANGS = ['javascript', 'typescript', 'python', 'java', 'go', 'rust', 'c', 'cpp', 'csharp', 'php', 'ruby', 'swift', 'kotlin', 'shell', 'sql'];

export function detect(content: string, filePath: string, _language: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const pat of PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pat.pattern.test(line)) {
        if (pat.antiPattern && pat.antiPattern.test(line)) continue;

        findings.push({
          id: `${pat.id}-${filePath}:${i + 1}`,
          ruleId: pat.id,
          title: pat.name,
          description: pat.description,
          severity: pat.severity,
          confidence: pat.confidence,
          filePath, line: i + 1,
          codeSnippet: getSnippet(lines, i),
          cwe: pat.cwe, owasp: 'A02',
          remediation: pat.remediation,
          fingerprint: generateFingerprint(pat.id, filePath, line.trim()),
        });
      }
    }
  }
  return findings;
}

export function detectSecretsOnly(content: string, filePath: string): Finding[] {
  return detect(content, filePath, 'generic');
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
