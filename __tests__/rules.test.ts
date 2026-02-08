import { describe, it, expect } from 'vitest';
import { ALL_RULES, getRulesForLanguage, getRuleById, getRulesByOwasp, getEnabledRules } from '../src/core/rules';
import { Severity } from '../src/core/severity';

describe('Rules Engine', () => {
  it('should have 100+ rules', () => {
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(100);
  });

  it('should have rules for each OWASP category', () => {
    const categories = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'];
    for (const cat of categories) {
      const rules = getRulesByOwasp(cat);
      expect(rules.length).toBeGreaterThan(0);
    }
  });

  it('should return rules for JavaScript', () => {
    const rules = getRulesForLanguage('javascript');
    expect(rules.length).toBeGreaterThan(20);
  });

  it('should return rules for Python', () => {
    const rules = getRulesForLanguage('python');
    expect(rules.length).toBeGreaterThan(10);
  });

  it('should return rules for Java', () => {
    const rules = getRulesForLanguage('java');
    expect(rules.length).toBeGreaterThan(5);
  });

  it('should find rule by ID', () => {
    const rule = getRuleById('INJ001');
    expect(rule).toBeDefined();
    expect(rule!.name).toContain('SQL Injection');
    expect(rule!.severity).toBe(Severity.CRITICAL);
  });

  it('should filter disabled rules', () => {
    const allRules = getEnabledRules();
    const filtered = getEnabledRules(['INJ001', 'INJ002']);
    expect(filtered.length).toBe(allRules.length - 2);
  });

  it('every rule should have required fields', () => {
    for (const rule of ALL_RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.severity).toBeTruthy();
      expect(rule.pattern).toBeInstanceOf(RegExp);
      expect(rule.languages.length).toBeGreaterThan(0);
      expect(rule.description).toBeTruthy();
      expect(rule.remediation).toBeTruthy();
    }
  });

  it('SQL injection rule should match vulnerable code', () => {
    const rule = getRuleById('INJ001')!;
    expect(rule.pattern.test('db.query("SELECT * FROM users WHERE id=" + userId)')).toBe(true);
  });

  it('SQL injection rule should match INSERT', () => {
    const rule = getRuleById('INJ001')!;
    expect(rule.pattern.test('db.query("INSERT INTO users VALUES(" + name + ")")')).toBe(true);
  });

  it('eval rule should match eval with variable', () => {
    const rule = getRuleById('INJ010')!;
    expect(rule.pattern.test('eval(userInput)')).toBe(true);
  });

  it('eval rule should not match eval with static string', () => {
    const rule = getRuleById('INJ010')!;
    expect(rule.pattern.test('eval("2+2")')).toBe(false);
  });

  it('AWS key pattern should match real format', () => {
    const rule = getRuleById('SEC001')!;
    expect(rule.pattern.test('AKIAIOSFODNN7EXAMPLE')).toBe(true);
  });

  it('GitHub token pattern should match', () => {
    const rule = getRuleById('SEC005')!;
    expect(rule.pattern.test('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij')).toBe(true);
  });

  it('private key pattern should match', () => {
    const rule = getRuleById('SEC004')!;
    expect(rule.pattern.test('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
    expect(rule.pattern.test('-----BEGIN PRIVATE KEY-----')).toBe(true);
  });

  it('TLS verification disabled pattern should match', () => {
    const rule = getRuleById('CRYPTO009')!;
    expect(rule.pattern.test('rejectUnauthorized: false')).toBe(true);
    expect(rule.pattern.test('verify = False')).toBe(true);
    expect(rule.pattern.test('InsecureSkipVerify: true')).toBe(true);
  });

  it('default credentials pattern should match common passwords', () => {
    const rule = getRuleById('CFG002')!;
    expect(rule.pattern.test('password: "admin"')).toBe(true);
    expect(rule.pattern.test("password = 'password'")).toBe(true);
    expect(rule.pattern.test('pwd: "123456"')).toBe(true);
  });

  it('CORS wildcard should match', () => {
    const rule = getRuleById('BAC004')!;
    expect(rule.pattern.test("Access-Control-Allow-Origin: '*'")).toBe(true);
  });

  it('command injection pattern should match', () => {
    const rule = getRuleById('INJ005')!;
    expect(rule.pattern.test('exec(`ls ${userInput}`)')).toBe(true);
  });
});
