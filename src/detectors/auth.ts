import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

interface DetectorPattern {
  id: string;
  name: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  cwe: string;
  pattern: RegExp;
  antiPattern?: RegExp;
  languages: string[];
  description: string;
  remediation: string;
}

const PATTERNS: DetectorPattern[] = [
  {
    id: 'AUTH-BYPASS-NONE-ALG', name: 'JWT None Algorithm', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-345', pattern: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    languages: ['javascript', 'typescript'],
    description: 'JWT accepts "none" algorithm, allowing signature bypass.',
    remediation: 'Explicitly set allowed algorithms: algorithms: ["HS256"] or ["RS256"].',
  },
  {
    id: 'AUTH-HARDCODED-JWT', name: 'Hardcoded JWT Secret', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', pattern: /(?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\([^)]*,\s*['"][^'"]{4,}['"]/i,
    languages: ['javascript', 'typescript'],
    description: 'JWT signing secret hardcoded in source code.',
    remediation: 'Use environment variables for JWT secrets.',
  },
  {
    id: 'AUTH-NO-EXPIRY', name: 'JWT Without Expiration', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-613', pattern: /jwt\.sign\s*\(\s*\{[^}]*\}\s*,/,
    antiPattern: /(?:expiresIn|exp\s*:|maxAge)/i,
    languages: ['javascript', 'typescript'],
    description: 'JWT created without expiration time.',
    remediation: 'Set token expiration: jwt.sign(payload, secret, { expiresIn: "1h" }).',
  },
  {
    id: 'AUTH-WEAK-PASSWORD', name: 'Weak Password Policy', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-521', pattern: /(?:password|passwd).*(?:min|length|minLength)\s*[:=<]\s*[1-7]\b/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'go'],
    description: 'Password minimum length is too short.',
    remediation: 'Enforce minimum 8-character passwords, ideally 12+.',
  },
  {
    id: 'AUTH-PLAINTEXT-PASS', name: 'Password Stored Without Hashing', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-256', pattern: /(?:user|account).*(?:password|passwd)\s*[:=]\s*(?:req\.|request\.|input\.|body\.)/i,
    antiPattern: /(?:hash|bcrypt|scrypt|argon|pbkdf|encrypt|crypt)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby'],
    description: 'Password from user input may be stored without hashing.',
    remediation: 'Hash passwords with bcrypt, scrypt, or argon2 before storage.',
  },
  {
    id: 'AUTH-SESSION-FIXATION', name: 'Session Fixation', severity: Severity.HIGH, confidence: 'low',
    cwe: 'CWE-384', pattern: /(?:login|authenticate|signIn)\s*(?:=|:|\().*(?:session|cookie)/i,
    antiPattern: /(?:regenerate|destroy|invalidate|new.*session)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    description: 'Login handler may not regenerate session ID.',
    remediation: 'Regenerate session ID after successful authentication.',
  },
  {
    id: 'AUTH-DEFAULT-CREDS', name: 'Default Credentials', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"](?:admin|password|123456|root|default|test|guest|letmein|welcome|12345678|qwerty|abc123)['"]/i,
    antiPattern: /(?:test|spec|mock|example|placeholder)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'csharp'],
    description: 'Default or commonly guessed password found in code.',
    remediation: 'Remove hardcoded credentials. Use environment variables or secret management.',
  },
  {
    id: 'AUTH-NO-LOCKOUT', name: 'Missing Account Lockout', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-307', pattern: /(?:login|authenticate|signIn)\s*(?:=|:|\().*(?:password|credential)/i,
    antiPattern: /(?:lockout|maxAttempts|failedAttempts|brute|throttle|rateLimit|delay)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    description: 'Login function without brute force protection.',
    remediation: 'Implement account lockout after N failed attempts.',
  },
  {
    id: 'AUTH-PASS-IN-URL', name: 'Password in URL', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-598', pattern: /(?:url|href|redirect|link|location).*[?&](?:password|passwd|pwd|secret|token)=/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'go', 'csharp'],
    description: 'Sensitive credential sent in URL query parameter.',
    remediation: 'Send credentials in request body or headers.',
  },
  {
    id: 'AUTH-MISSING-MIDDLEWARE', name: 'Route Without Auth Middleware', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-862', pattern: /(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]\/(?:admin|api\/admin|dashboard|settings|users?\/\w|account)/i,
    antiPattern: /(?:auth|protect|guard|session|verify|middleware|isAuthenticated|requireAuth|passport)/i,
    languages: ['javascript', 'typescript'],
    description: 'Sensitive route may lack authentication middleware.',
    remediation: 'Add authentication middleware before the route handler.',
  },
  {
    id: 'AUTH-PRIVILEGE-ESCALATION', name: 'Privilege Escalation Risk', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-269', pattern: /(?:role|isAdmin|is_admin|permission|privilege)\s*=\s*(?:req\.|request\.|params|body|query|input)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php'],
    description: 'User role or admin status set from user-controlled input.',
    remediation: 'Derive roles from server-side session data, never from user input.',
  },
];

export function detect(content: string, filePath: string, language: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  for (const pat of PATTERNS) {
    if (!pat.languages.includes(language)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (pat.pattern.test(line)) {
        if (pat.antiPattern) {
          const contextStart = Math.max(0, i - 5);
          const contextEnd = Math.min(lines.length, i + 6);
          const context = lines.slice(contextStart, contextEnd).join('\n');
          if (pat.antiPattern.test(context)) continue;
        }

        findings.push({
          id: `${pat.id}-${filePath}:${i + 1}`,
          ruleId: pat.id,
          title: pat.name,
          description: pat.description,
          severity: pat.severity,
          confidence: pat.confidence,
          filePath,
          line: i + 1,
          codeSnippet: getSnippet(lines, i),
          cwe: pat.cwe,
          owasp: 'A07',
          remediation: pat.remediation,
          fingerprint: generateFingerprint(pat.id, filePath, line.trim()),
        });
      }
    }
  }

  return findings;
}

function getSnippet(lines: string[], index: number, context: number = 2): string {
  const start = Math.max(0, index - context);
  const end = Math.min(lines.length, index + context + 1);
  return lines.slice(start, end)
    .map((l, i) => {
      const lineNum = start + i + 1;
      const marker = (start + i === index) ? '>' : ' ';
      return `${marker} ${lineNum} | ${l}`;
    })
    .join('\n');
}
