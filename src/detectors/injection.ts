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
    id: 'INJ-SQL-CONCAT', name: 'SQL Injection (String Concatenation)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', pattern: /(?:query|execute|exec|raw|prepare)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b[^'"`]*['"`]\s*\+/i,
    languages: ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'go'],
    description: 'SQL query constructed via string concatenation with potential user input.',
    remediation: 'Use parameterized queries or prepared statements.',
  },
  {
    id: 'INJ-SQL-TEMPLATE', name: 'SQL Injection (Template Literal)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', pattern: /(?:query|execute|exec|raw)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`]*\$\{/i,
    languages: ['javascript', 'typescript'],
    description: 'SQL query built with template literals containing interpolated values.',
    remediation: 'Use parameterized queries or tagged template literals (e.g., sql`...`).',
  },
  {
    id: 'INJ-SQL-FSTRING', name: 'SQL Injection (f-string/format)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', pattern: /(?:execute|cursor)\s*\(\s*(?:f['"]|['"].*['"]\s*\.format\s*\(|['"].*['"]\s*%\s*)/i,
    antiPattern: /(?:parameterize|placeholder|%s.*,\s*\(|%s.*,\s*\[)/,
    languages: ['python'],
    description: 'SQL query built with Python f-string or .format().',
    remediation: 'Use parameterized queries with %s placeholders and tuple arguments.',
  },
  {
    id: 'INJ-CMD-EXEC', name: 'Command Injection', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-78', pattern: /(?:child_process|exec|execSync|spawn|spawnSync|system|popen|subprocess)\s*[\(.]\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+\s*\w|f['"])/i,
    languages: ['javascript', 'typescript', 'python', 'ruby', 'php'],
    description: 'Operating system command built with dynamic input.',
    remediation: 'Use execFile with argument arrays. Never construct commands from user input.',
  },
  {
    id: 'INJ-XSS-INNERHTML', name: 'XSS via innerHTML', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-79', pattern: /\.innerHTML\s*=\s*(?!['"](?:<br\s*\/?>|<hr\s*\/?>|<p>|<div>|<span>)['"])/,
    languages: ['javascript', 'typescript'],
    description: 'Setting innerHTML with potentially untrusted content.',
    remediation: 'Use textContent for plain text, or sanitize with DOMPurify before innerHTML.',
  },
  {
    id: 'INJ-XSS-DOCWRITE', name: 'XSS via document.write', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-79', pattern: /document\.write(?:ln)?\s*\(/,
    languages: ['javascript', 'typescript'],
    description: 'document.write() can introduce XSS vulnerabilities.',
    remediation: 'Use DOM manipulation methods instead.',
  },
  {
    id: 'INJ-XSS-REACT', name: 'XSS via dangerouslySetInnerHTML', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-79', pattern: /dangerouslySetInnerHTML/,
    antiPattern: /(?:DOMPurify|sanitize|purify|xss|escape)/i,
    languages: ['javascript', 'typescript'],
    description: 'React dangerouslySetInnerHTML used without visible sanitization.',
    remediation: 'Sanitize content with DOMPurify before using dangerouslySetInnerHTML.',
  },
  {
    id: 'INJ-EVAL', name: 'Code Injection via eval()', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-95', pattern: /\beval\s*\(\s*(?!['"][^'"]*['"])/,
    languages: ['javascript', 'typescript', 'python', 'php', 'ruby'],
    description: 'eval() with dynamic input enables arbitrary code execution.',
    remediation: 'Avoid eval(). Use JSON.parse() for data, or purpose-built parsers.',
  },
  {
    id: 'INJ-LDAP', name: 'LDAP Injection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-90', pattern: /(?:ldap|LDAP).*(?:search|bind|modify|add)\s*\(.*(?:\+\s*\w|`[^`]*\$\{|\.format|%s)/,
    languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
    description: 'LDAP query built with dynamic string construction.',
    remediation: 'Escape special LDAP characters and use parameterized filters.',
  },
  {
    id: 'INJ-NOSQL', name: 'NoSQL Injection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-943', pattern: /(?:find|findOne|deleteOne|updateOne|aggregate)\s*\(\s*(?:req\.body|req\.query|req\.params|request\.\w)/,
    languages: ['javascript', 'typescript'],
    description: 'MongoDB query using raw user input without sanitization.',
    remediation: 'Validate input types and use query builders. Reject $-prefixed keys.',
  },
  {
    id: 'INJ-SSTI', name: 'Server-Side Template Injection', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-1336', pattern: /(?:render_template_string|Template\s*\(|nunjucks\.renderString|ejs\.render)\s*\(\s*(?:req|request|input|user)/i,
    languages: ['javascript', 'typescript', 'python'],
    description: 'User input passed directly as template source.',
    remediation: 'Never use user input as template source. Use data binding with template files.',
  },
  {
    id: 'INJ-XPATH', name: 'XPath Injection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-643', pattern: /(?:xpath|selectNodes?|evaluate)\s*\(.*(?:\+\s*\w|`[^`]*\$\{|\.format)/,
    languages: ['javascript', 'typescript', 'python', 'java', 'csharp', 'php'],
    description: 'XPath query built with dynamic input.',
    remediation: 'Use parameterized XPath queries.',
  },
  {
    id: 'INJ-HEADER', name: 'HTTP Header Injection', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-113', pattern: /(?:setHeader|writeHead|header)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:req\.|request\.|input|user)/i,
    languages: ['javascript', 'typescript', 'python', 'php'],
    description: 'HTTP header value set from user input.',
    remediation: 'Validate and sanitize header values. Reject newline characters.',
  },
  {
    id: 'INJ-REGEX', name: 'ReDoS (Regular Expression DoS)', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-1333', pattern: /new\s+RegExp\s*\(\s*(?:req\.|request\.|input|user|param|query|body|arg)/i,
    languages: ['javascript', 'typescript'],
    description: 'Regular expression constructed from user input — ReDoS risk.',
    remediation: 'Escape user input or use RE2 for safe regex evaluation.',
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
        if (pat.antiPattern && pat.antiPattern.test(line)) continue;

        // Check surrounding context for anti-patterns
        if (pat.antiPattern) {
          const contextStart = Math.max(0, i - 3);
          const contextEnd = Math.min(lines.length, i + 4);
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
          owasp: 'A03',
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
