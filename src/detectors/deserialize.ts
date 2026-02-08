import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';

const PATTERNS = [
  {
    id: 'DESER-JS', name: 'Insecure Deserialization (JS)', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['javascript', 'typescript'],
    pattern: /(?:serialize|node-serialize|funcster|cryo)\s*\.\s*(?:unserialize|parse|deserialize)\s*\(/i,
    description: 'Node.js deserialization of untrusted data can lead to RCE.',
    remediation: 'Avoid native serialization. Use JSON for data exchange.',
  },
  {
    id: 'DESER-YAML-JS', name: 'Unsafe YAML Loading (JS)', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['javascript', 'typescript'],
    pattern: /js-yaml\.load\s*\(/,
    antiPattern: /(?:safeLoad|schema.*SAFE|JSON_SCHEMA|FAILSAFE)/i,
    description: 'js-yaml.load() without safe schema can execute code.',
    remediation: 'Use yaml.load(data, { schema: SAFE_SCHEMA }) or yaml.safeLoad().',
  },
  {
    id: 'DESER-PICKLE', name: 'Insecure Deserialization (Python pickle)', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['python'],
    pattern: /(?:pickle\.loads?|cPickle\.loads?|shelve\.open|dill\.loads?)\s*\(/,
    description: 'Python pickle deserialization enables arbitrary code execution.',
    remediation: 'Avoid pickle for untrusted data. Use JSON or protocol buffers.',
  },
  {
    id: 'DESER-YAML-PY', name: 'Unsafe YAML Loading (Python)', severity: Severity.HIGH, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['python'],
    pattern: /yaml\.(?:load|unsafe_load)\s*\(/,
    antiPattern: /(?:safe_load|SafeLoader|Loader\s*=\s*(?:yaml\.)?SafeLoader)/,
    description: 'yaml.load() without SafeLoader enables code execution.',
    remediation: 'Use yaml.safe_load() or yaml.load(data, Loader=SafeLoader).',
  },
  {
    id: 'DESER-JAVA', name: 'Insecure Deserialization (Java)', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['java', 'kotlin'],
    pattern: /(?:ObjectInputStream|readObject\s*\(|XMLDecoder|XStream|Kryo\.readObject|Hessian)\s*[\.(]/,
    antiPattern: /(?:ObjectInputFilter|whitelist|allowlist|resolveClass)/i,
    description: 'Java native deserialization enables RCE.',
    remediation: 'Use allowlist-based ObjectInputFilter or avoid native serialization.',
  },
  {
    id: 'DESER-PHP', name: 'Insecure Deserialization (PHP)', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['php'],
    pattern: /(?:unserialize|phpunserialize)\s*\(\s*\$/,
    description: 'PHP unserialize() with user input enables object injection.',
    remediation: 'Use json_decode() instead. If using unserialize, set allowed_classes.',
  },
  {
    id: 'DESER-RUBY', name: 'Insecure Deserialization (Ruby)', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['ruby'],
    pattern: /(?:Marshal\.load|YAML\.load|Psych\.load)\s*\(/,
    antiPattern: /(?:safe_load|permitted_classes)/i,
    description: 'Ruby deserialization of untrusted data.',
    remediation: 'Use YAML.safe_load or JSON.parse instead.',
  },
  {
    id: 'DESER-DOTNET', name: 'Insecure Deserialization (.NET)', severity: Severity.CRITICAL, confidence: 'high' as const,
    cwe: 'CWE-502', languages: ['csharp'],
    pattern: /(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter|LosFormatter)\.Deserialize\s*\(/,
    description: '.NET deserialization with unsafe formatters.',
    remediation: 'Use System.Text.Json or Newtonsoft.Json instead.',
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
          if (pat.antiPattern.test(lines.slice(cs, ce).join('\n'))) continue;
        }
        findings.push({
          id: `${pat.id}-${filePath}:${i + 1}`,
          ruleId: pat.id, title: pat.name, description: pat.description,
          severity: pat.severity, confidence: pat.confidence,
          filePath, line: i + 1,
          codeSnippet: getSnippet(lines, i),
          cwe: pat.cwe, owasp: 'A08',
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
