import { Finding, Severity } from '../core/severity';
import { generateFingerprint } from '../utils/fingerprint';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

export function detect(content: string, filePath: string, _language: string): Finding[] {
  const findings: Finding[] = [];
  const basename = path.basename(filePath);

  if (basename === 'package.json') {
    findings.push(...checkPackageJson(content, filePath));
  } else if (basename === 'requirements.txt' || basename === 'Pipfile') {
    findings.push(...checkPythonDeps(content, filePath));
  } else if (basename === 'pom.xml') {
    findings.push(...checkMavenDeps(content, filePath));
  } else if (basename === 'go.mod') {
    findings.push(...checkGoDeps(content, filePath));
  } else if (basename === 'Gemfile') {
    findings.push(...checkRubyDeps(content, filePath));
  }

  return findings;
}

function checkPackageJson(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  try {
    const pkg = JSON.parse(content);
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

    // Check for wildcard or latest versions
    const lines = content.split('\n');
    for (const [name, version] of Object.entries(allDeps)) {
      const ver = version as string;
      if (ver === '*' || ver === 'latest' || ver === '') {
        const lineNum = findLine(lines, name);
        findings.push({
          id: `DEP-WILDCARD-${filePath}:${lineNum}`,
          ruleId: 'DEP-WILDCARD',
          title: `Wildcard Dependency: ${name}`,
          description: `Package "${name}" uses wildcard version "${ver}". This can introduce breaking changes or vulnerabilities.`,
          severity: Severity.MEDIUM,
          confidence: 'high',
          filePath, line: lineNum,
          codeSnippet: getSnippetFromLines(lines, lineNum - 1),
          cwe: 'CWE-1104', owasp: 'A06',
          remediation: 'Pin to a specific version range (e.g., ^1.2.3).',
          fingerprint: generateFingerprint('DEP-WILDCARD', filePath, name),
        });
      }
    }

    // Check for known vulnerable packages
    const knownVulnerable: Record<string, { maxSafe: string; cve: string; desc: string }> = {
      'lodash': { maxSafe: '4.17.21', cve: 'CVE-2021-23337', desc: 'Prototype pollution in lodash' },
      'minimist': { maxSafe: '1.2.6', cve: 'CVE-2021-44906', desc: 'Prototype pollution in minimist' },
      'node-fetch': { maxSafe: '2.6.7', cve: 'CVE-2022-0235', desc: 'Exposure of sensitive information' },
      'express': { maxSafe: '4.18.2', cve: 'CVE-2024-29041', desc: 'Open redirect in express' },
      'axios': { maxSafe: '1.6.0', cve: 'CVE-2023-45857', desc: 'CSRF in axios' },
      'jsonwebtoken': { maxSafe: '9.0.0', cve: 'CVE-2022-23529', desc: 'Insecure default algorithm' },
    };

    for (const [name, info] of Object.entries(knownVulnerable)) {
      if (allDeps[name]) {
        const lineNum = findLine(lines, name);
        findings.push({
          id: `DEP-VULN-${name}-${filePath}:${lineNum}`,
          ruleId: 'DEP-KNOWN-VULN',
          title: `Potentially Vulnerable: ${name}`,
          description: `${info.desc} (${info.cve}). Check if version is below ${info.maxSafe}.`,
          severity: Severity.MEDIUM,
          confidence: 'low',
          filePath, line: lineNum,
          codeSnippet: getSnippetFromLines(lines, lineNum - 1),
          cwe: 'CWE-1035', owasp: 'A06',
          remediation: `Update ${name} to version ${info.maxSafe} or later.`,
          fingerprint: generateFingerprint('DEP-KNOWN-VULN', filePath, name),
        });
      }
    }
  } catch {
    // Invalid JSON — skip
  }
  return findings;
}

function checkPythonDeps(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const knownVuln: Record<string, string> = {
    'django': 'CVE-2023-46695',
    'flask': 'CVE-2023-30861',
    'requests': 'CVE-2023-32681',
    'pillow': 'CVE-2023-44271',
    'pyyaml': 'CVE-2020-14343',
    'jinja2': 'CVE-2024-22195',
  };

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([a-zA-Z0-9_-]+)/);
    if (match) {
      const pkg = match[1].toLowerCase();
      if (knownVuln[pkg]) {
        findings.push({
          id: `DEP-PY-${pkg}-${filePath}:${i + 1}`,
          ruleId: 'DEP-PYTHON-VULN',
          title: `Check Python Package: ${pkg}`,
          description: `Package ${pkg} has known vulnerability ${knownVuln[pkg]}. Verify version.`,
          severity: Severity.MEDIUM, confidence: 'low',
          filePath, line: i + 1,
          codeSnippet: getSnippetFromLines(lines, i),
          cwe: 'CWE-1035', owasp: 'A06',
          remediation: `Update ${pkg} to the latest patched version.`,
          fingerprint: generateFingerprint('DEP-PYTHON-VULN', filePath, pkg),
        });
      }
    }
  }
  return findings;
}

function checkMavenDeps(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const knownVuln = ['log4j', 'commons-collections', 'struts', 'spring-core'];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pkg of knownVuln) {
      if (line.includes(pkg)) {
        findings.push({
          id: `DEP-MAVEN-${pkg}-${filePath}:${i + 1}`,
          ruleId: 'DEP-MAVEN-VULN',
          title: `Check Maven Dependency: ${pkg}`,
          description: `Package ${pkg} has a history of critical vulnerabilities. Verify version.`,
          severity: Severity.MEDIUM, confidence: 'low',
          filePath, line: i + 1,
          codeSnippet: getSnippetFromLines(lines, i),
          cwe: 'CWE-1035', owasp: 'A06',
          remediation: `Update ${pkg} to the latest patched version.`,
          fingerprint: generateFingerprint('DEP-MAVEN-VULN', filePath, pkg),
        });
      }
    }
  }
  return findings;
}

function checkGoDeps(content: string, filePath: string): Finding[] {
  return []; // Go module checking would require network access
}

function checkRubyDeps(content: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  const knownVuln = ['rails', 'rack', 'actionpack', 'activesupport'];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const pkg of knownVuln) {
      if (line.includes(`'${pkg}'`) || line.includes(`"${pkg}"`)) {
        findings.push({
          id: `DEP-RUBY-${pkg}-${filePath}:${i + 1}`,
          ruleId: 'DEP-RUBY-VULN',
          title: `Check Ruby Gem: ${pkg}`,
          description: `Gem ${pkg} has known vulnerabilities. Verify version.`,
          severity: Severity.MEDIUM, confidence: 'low',
          filePath, line: i + 1,
          codeSnippet: getSnippetFromLines(lines, i),
          cwe: 'CWE-1035', owasp: 'A06',
          remediation: `Update ${pkg} to the latest patched version.`,
          fingerprint: generateFingerprint('DEP-RUBY-VULN', filePath, pkg),
        });
      }
    }
  }
  return findings;
}

export function runNpmAudit(projectDir: string): Finding[] {
  const findings: Finding[] = [];
  try {
    const lockPath = path.join(projectDir, 'package-lock.json');
    if (!fs.existsSync(lockPath)) return findings;

    const result = execSync('npm audit --json 2>/dev/null', {
      cwd: projectDir,
      timeout: 30000,
      encoding: 'utf-8',
    });

    const audit = JSON.parse(result);
    if (audit.vulnerabilities) {
      for (const [name, info] of Object.entries(audit.vulnerabilities) as [string, any][]) {
        const severity = info.severity === 'critical' ? Severity.CRITICAL
          : info.severity === 'high' ? Severity.HIGH
          : info.severity === 'moderate' ? Severity.MEDIUM
          : Severity.LOW;

        findings.push({
          id: `NPM-AUDIT-${name}`,
          ruleId: 'DEP-NPM-AUDIT',
          title: `Vulnerable Package: ${name}`,
          description: `${info.via?.[0]?.title || 'Known vulnerability'} in ${name}@${info.range || 'unknown'}`,
          severity, confidence: 'high',
          filePath: path.join(projectDir, 'package.json'),
          line: 1,
          codeSnippet: `${name}: ${info.range || 'unknown version'}`,
          cwe: info.via?.[0]?.cwe?.[0] || 'CWE-1035',
          owasp: 'A06',
          remediation: info.fixAvailable ? `Run: npm audit fix` : `Update ${name} manually.`,
          fingerprint: generateFingerprint('DEP-NPM-AUDIT', name, info.range || ''),
        });
      }
    }
  } catch {
    // npm audit failed or not available
  }
  return findings;
}

function findLine(lines: string[], searchTerm: string): number {
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(searchTerm)) return i + 1;
  }
  return 1;
}

function getSnippetFromLines(lines: string[], index: number, context = 2): string {
  const start = Math.max(0, index - context);
  const end = Math.min(lines.length, index + context + 1);
  return lines.slice(start, end).map((l, i) => {
    const lineNum = start + i + 1;
    const marker = (start + i === index) ? '>' : ' ';
    return `${marker} ${lineNum} | ${l}`;
  }).join('\n');
}
