import { describe, it, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { scan, scanFile } from '../src/core/scanner';
import { generateReport } from '../src/core/reporter';
import { Severity } from '../src/core/severity';
import { detectLanguage, isSupportedFile } from '../src/utils/languages';
import { generateFingerprint, deduplicateFindings } from '../src/utils/fingerprint';

describe('Scanner', () => {
  it('should scan a single file', () => {
    const code = `
const password = "admin";
eval(userInput);
db.query("SELECT * FROM users WHERE id=" + userId);
`;
    const findings = scanFile('test.js', code, 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect multiple vulnerability types', () => {
    const code = `
eval(userInput);
db.query("SELECT * FROM users WHERE id=" + userId);
element.innerHTML = userData;
const key = "AKIAIOSFODNN7EXAMPLE";
`;
    const findings = scanFile('test.js', code, 'javascript');
    const ruleIds = new Set(findings.map(f => f.ruleId));
    expect(ruleIds.size).toBeGreaterThanOrEqual(3);
  });

  it('should scan a directory', async () => {
    // Create temp dir with test files
    const tmpDir = path.join(os.tmpdir(), 'ghostpatch-test-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });

    fs.writeFileSync(path.join(tmpDir, 'test.js'), `
const password = "admin";
eval(userInput);
`);
    fs.writeFileSync(path.join(tmpDir, 'safe.js'), `
const x = 1 + 2;
console.log(x);
`);

    try {
      const result = await scan(tmpDir, { severity: Severity.LOW });
      expect(result.filesScanned).toBeGreaterThanOrEqual(2);
      expect(result.findings.length).toBeGreaterThan(0);
      expect(result.summary.total).toBe(result.findings.length);
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should filter by severity', async () => {
    const code = `
const password = "admin";
eval(userInput);
element.innerHTML = userData;
const x = Math.random();
const opts = { secure: false, httpOnly: false };
`;
    const allFindings = scanFile('test.js', code, 'javascript');
    const criticalFindings = allFindings.filter(f => f.severity === Severity.CRITICAL);
    expect(allFindings.length).toBeGreaterThan(0);
    expect(criticalFindings.length).toBeGreaterThan(0);
    expect(criticalFindings.length).toBeLessThanOrEqual(allFindings.length);
  });

  it('should include code snippets', () => {
    const code = `line1
line2
eval(userInput);
line4
line5`;
    const findings = scanFile('test.js', code, 'javascript');
    const evalFinding = findings.find(f => f.ruleId.includes('EVAL'));
    if (evalFinding) {
      expect(evalFinding.codeSnippet).toContain('eval');
      expect(evalFinding.line).toBe(3);
    }
  });

  it('should produce valid fingerprints', () => {
    const code = 'eval(userInput);';
    const findings = scanFile('test.js', code, 'javascript');
    for (const f of findings) {
      expect(f.fingerprint).toBeTruthy();
      expect(f.fingerprint.length).toBe(16);
    }
  });
});

describe('Reporter', () => {
  it('should generate terminal report', async () => {
    const tmpDir = path.join(os.tmpdir(), 'ghostpatch-report-test-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'test.js'), 'eval(userInput);');

    try {
      const result = await scan(tmpDir);
      const report = generateReport(result, 'terminal');
      expect(report).toContain('GhostPatch');
      expect(report).toContain('CRITICAL');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should generate JSON report', async () => {
    const tmpDir = path.join(os.tmpdir(), 'ghostpatch-json-test-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'test.js'), 'eval(userInput);');

    try {
      const result = await scan(tmpDir);
      const json = generateReport(result, 'json');
      const parsed = JSON.parse(json);
      expect(parsed.ghostpatch.version).toBe('1.0.0');
      expect(Array.isArray(parsed.findings)).toBe(true);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should generate SARIF report', async () => {
    const tmpDir = path.join(os.tmpdir(), 'ghostpatch-sarif-test-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'test.js'), 'eval(userInput);');

    try {
      const result = await scan(tmpDir);
      const sarif = generateReport(result, 'sarif');
      const parsed = JSON.parse(sarif);
      expect(parsed.version).toBe('2.1.0');
      expect(parsed.runs).toBeDefined();
      expect(parsed.runs[0].tool.driver.name).toBe('GhostPatch');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should generate HTML report', async () => {
    const tmpDir = path.join(os.tmpdir(), 'ghostpatch-html-test-' + Date.now());
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'test.js'), 'eval(userInput);');

    try {
      const result = await scan(tmpDir);
      const html = generateReport(result, 'html');
      expect(html).toContain('<!DOCTYPE html>');
      expect(html).toContain('GhostPatch');
      expect(html).toContain('Security Report');
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});

describe('Language Detection', () => {
  it('should detect JavaScript', () => {
    expect(detectLanguage('test.js')).toBe('javascript');
    expect(detectLanguage('test.jsx')).toBe('javascript');
    expect(detectLanguage('test.mjs')).toBe('javascript');
  });

  it('should detect TypeScript', () => {
    expect(detectLanguage('test.ts')).toBe('typescript');
    expect(detectLanguage('test.tsx')).toBe('typescript');
  });

  it('should detect Python', () => {
    expect(detectLanguage('test.py')).toBe('python');
  });

  it('should detect Java', () => {
    expect(detectLanguage('Test.java')).toBe('java');
  });

  it('should detect Go', () => {
    expect(detectLanguage('main.go')).toBe('go');
  });

  it('should return null for unsupported files', () => {
    expect(detectLanguage('test.txt')).toBeNull();
    expect(detectLanguage('image.png')).toBeNull();
  });

  it('should identify supported files', () => {
    expect(isSupportedFile('test.ts')).toBe(true);
    expect(isSupportedFile('test.py')).toBe(true);
    expect(isSupportedFile('test.txt')).toBe(false);
  });
});

describe('Fingerprinting', () => {
  it('should generate consistent fingerprints', () => {
    const fp1 = generateFingerprint('rule1', 'file1', 'content');
    const fp2 = generateFingerprint('rule1', 'file1', 'content');
    expect(fp1).toBe(fp2);
  });

  it('should generate different fingerprints for different inputs', () => {
    const fp1 = generateFingerprint('rule1', 'file1', 'content1');
    const fp2 = generateFingerprint('rule1', 'file1', 'content2');
    expect(fp1).not.toBe(fp2);
  });

  it('should deduplicate findings', () => {
    const findings = [
      { fingerprint: 'aaa', title: 'Finding 1' },
      { fingerprint: 'bbb', title: 'Finding 2' },
      { fingerprint: 'aaa', title: 'Finding 1 duplicate' },
    ];
    const deduped = deduplicateFindings(findings);
    expect(deduped.length).toBe(2);
  });
});
