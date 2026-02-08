import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'CRYPTO-MD5', name: 'Weak Hash (MD5)', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-328', pattern: /(?:md5|MD5)\s*[\(.<]/,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp', 'c', 'cpp'],
    description: 'MD5 is cryptographically broken.', remediation: 'Use SHA-256+ for integrity, bcrypt/argon2 for passwords.',
  },
  {
    id: 'CRYPTO-SHA1', name: 'Weak Hash (SHA-1)', severity: Severity.MEDIUM, confidence: 'high' as const,
    cwe: 'CWE-328', pattern: /(?:sha-?1|SHA-?1)\s*[\(.<'"]/,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp'],
    description: 'SHA-1 is deprecated for security use.', remediation: 'Use SHA-256 or stronger.',
  },
  {
    id: 'CRYPTO-WEAK-CIPHER', name: 'Weak Cipher Algorithm', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-327', pattern: /(?:createCipher(?:iv)?\s*\(\s*['"](?:des|rc4|rc2|blowfish)|DES(?:ede)?|RC4|Blowfish)\b/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp'],
    description: 'Weak or broken cipher algorithm.', remediation: 'Use AES-256-GCM or ChaCha20-Poly1305.',
  },
  {
    id: 'CRYPTO-ECB', name: 'ECB Mode', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-327', pattern: /(?:aes.*ecb|ECB|\.ECB|mode.*ecb|ecb.*mode)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp'],
    description: 'ECB mode does not provide semantic security.', remediation: 'Use GCM or CBC with HMAC.',
  },
  {
    id: 'CRYPTO-MATH-RANDOM', name: 'Insecure Random (Math.random)', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-330', pattern: /Math\.random\s*\(\)/,
    antiPattern: /(?:test|mock|sample|example|demo|shuffle|color|animation|ui|css|game|placeholder)/i,
    languages: ['javascript', 'typescript'],
    description: 'Math.random() is not cryptographically secure.', remediation: 'Use crypto.randomBytes() or crypto.getRandomValues().',
  },
  {
    id: 'CRYPTO-HARDCODED-KEY', name: 'Hardcoded Encryption Key', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-321', pattern: /(?:(?:encryption|encrypt|cipher|aes|secret)[-_]?key)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    antiPattern: /(?:process\.env|os\.environ|config\.|env\[|example|placeholder|your_)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp'],
    description: 'Hardcoded encryption key in source code.', remediation: 'Use environment variables or key management service.',
  },
  {
    id: 'CRYPTO-HARDCODED-IV', name: 'Hardcoded IV/Nonce', severity: Severity.HIGH, confidence: 'medium' as const,
    cwe: 'CWE-329', pattern: /(?:iv|nonce|IV|NONCE)\s*[:=]\s*(?:['"][^'"]{8,}['"]|Buffer\.from\s*\(\s*['"])/,
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    description: 'Hardcoded initialization vector.', remediation: 'Generate unique random IV per encryption operation.',
  },
  {
    id: 'CRYPTO-TLS-DISABLED', name: 'TLS Verification Disabled', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-295', pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|SSL_VERIFY_NONE|check_hostname\s*=\s*False)/,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby'],
    description: 'TLS certificate verification disabled.', remediation: 'Always verify TLS certificates in production.',
  },
  {
    id: 'CRYPTO-WEAK-PASS-HASH', name: 'Plain Hash for Password', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-916', pattern: /(?:createHash\s*\(\s*['"](?:md5|sha1|sha256)['"]|hashlib\.(?:md5|sha1|sha256))\s*[(.]/,
    antiPattern: /(?:hmac|pbkdf2|checksum|file.*hash|integrity|verify)/i,
    languages: ['javascript', 'typescript', 'python'],
    description: 'Plain hash used for password storage.', remediation: 'Use bcrypt, scrypt, or argon2 for password hashing.',
  },
  {
    id: 'CRYPTO-SMALL-KEY', name: 'Insufficient Key Length', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-326', pattern: /(?:generateKeyPair|RSA|keySize|modulusLength)\s*[:(]\s*(?:512|768|1024)\b/,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'csharp'],
    description: 'RSA key length below 2048 bits.', remediation: 'Use at least 2048-bit RSA keys.',
  },
  {
    id: 'CRYPTO-HTTP', name: 'Unencrypted HTTP', severity: Severity.MEDIUM, confidence: 'medium' as const,
    cwe: 'CWE-319', pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|example\.com)[^'"]+['"]/,
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp'],
    description: 'Unencrypted HTTP URL for non-local endpoint.', remediation: 'Use HTTPS for all external communications.',
  },
  {
    id: 'CRYPTO-TIMING', name: 'Timing Attack Vulnerable Comparison', severity: Severity.MEDIUM, confidence: 'low' as const,
    cwe: 'CWE-208', pattern: /(?:===?\s*(?:password|token|secret|apiKey|hash)|(?:password|token|secret|apiKey|hash)\s*===?)/i,
    antiPattern: /(?:timingSafe|constantTime|hmac\.compare|secrets\.compare_digest)/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'go'],
    description: 'String comparison for secrets vulnerable to timing attacks.', remediation: 'Use crypto.timingSafeEqual() for secret comparison.',
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
          const cs = Math.max(0, i - 3);
          const ce = Math.min(lines.length, i + 4);
          const ctx = lines.slice(cs, ce).join('\n');
          if (pat.antiPattern.test(ctx)) continue;
        }

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
