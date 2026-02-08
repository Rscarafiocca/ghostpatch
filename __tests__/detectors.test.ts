import { describe, it, expect } from 'vitest';
import * as injectionDetector from '../src/detectors/injection';
import * as authDetector from '../src/detectors/auth';
import * as cryptoDetector from '../src/detectors/crypto';
import * as secretsDetector from '../src/detectors/secrets';
import * as ssrfDetector from '../src/detectors/ssrf';
import * as pathTraversalDetector from '../src/detectors/pathtraversal';
import * as prototypeDetector from '../src/detectors/prototype';
import * as deserializeDetector from '../src/detectors/deserialize';
import * as misconfigDetector from '../src/detectors/misconfig';
import { Severity } from '../src/core/severity';

describe('Injection Detector', () => {
  it('should detect SQL injection via concatenation', () => {
    const code = `
const userId = req.params.id;
db.query("SELECT * FROM users WHERE id=" + userId);
`;
    const findings = injectionDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe(Severity.CRITICAL);
    expect(findings[0].ruleId).toContain('SQL');
  });

  it('should detect SQL injection via template literal', () => {
    const code = 'db.query(`SELECT * FROM users WHERE id=${userId}`);';
    const findings = injectionDetector.detect(code, 'test.ts', 'typescript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect eval usage', () => {
    const code = 'eval(userInput);';
    const findings = injectionDetector.detect(code, 'test.js', 'javascript');
    const evalFindings = findings.filter(f => f.ruleId.includes('EVAL'));
    expect(evalFindings.length).toBeGreaterThan(0);
    expect(evalFindings[0].severity).toBe(Severity.CRITICAL);
  });

  it('should detect XSS via innerHTML', () => {
    const code = 'element.innerHTML = userData;';
    const findings = injectionDetector.detect(code, 'test.js', 'javascript');
    const xssFindings = findings.filter(f => f.ruleId.includes('XSS'));
    expect(xssFindings.length).toBeGreaterThan(0);
  });

  it('should detect command injection', () => {
    const code = 'exec(`rm -rf ${req.body.path}`);';
    const findings = injectionDetector.detect(code, 'test.js', 'javascript');
    const cmdFindings = findings.filter(f => f.ruleId.includes('CMD'));
    expect(cmdFindings.length).toBeGreaterThan(0);
  });

  it('should detect NoSQL injection', () => {
    const code = 'User.findOne(req.body);';
    const findings = injectionDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should not flag safe code', () => {
    const code = `
const name = "hello";
console.log(name);
const x = 1 + 2;
`;
    const findings = injectionDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBe(0);
  });
});

describe('Auth Detector', () => {
  it('should detect hardcoded JWT secret', () => {
    const code = 'jwt.sign(payload, "mySecretKey123456");';
    const findings = authDetector.detect(code, 'test.js', 'javascript');
    const jwtFindings = findings.filter(f => f.ruleId.includes('JWT'));
    expect(jwtFindings.length).toBeGreaterThan(0);
  });

  it('should detect default credentials', () => {
    const code = 'const password = "admin";';
    const findings = authDetector.detect(code, 'test.js', 'javascript');
    const credFindings = findings.filter(f => f.ruleId.includes('DEFAULT'));
    expect(credFindings.length).toBeGreaterThan(0);
  });

  it('should detect privilege escalation', () => {
    const code = 'user.role = req.body.role;';
    const findings = authDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('Crypto Detector', () => {
  it('should detect MD5 usage', () => {
    const code = 'const hash = md5(data);';
    const findings = cryptoDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect Math.random for security', () => {
    const code = 'const token = Math.random().toString(36);';
    const findings = cryptoDetector.detect(code, 'test.js', 'javascript');
    const randomFindings = findings.filter(f => f.ruleId.includes('RANDOM'));
    expect(randomFindings.length).toBeGreaterThan(0);
  });

  it('should detect TLS verification disabled', () => {
    const code = '{ rejectUnauthorized: false }';
    const findings = cryptoDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('Secrets Detector', () => {
  it('should detect AWS access key', () => {
    const code = 'const key = "AKIAIOSFODNN7REALKEY1";';
    const findings = secretsDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe(Severity.CRITICAL);
  });

  it('should detect GitHub token', () => {
    const code = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";';
    const findings = secretsDetector.detect(code, 'test.js', 'javascript');
    const ghFindings = findings.filter(f => f.ruleId.includes('GITHUB'));
    expect(ghFindings.length).toBeGreaterThan(0);
  });

  it('should detect private key', () => {
    const code = '-----BEGIN RSA PRIVATE KEY-----';
    const findings = secretsDetector.detect(code, 'test.pem', 'generic');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect database connection string', () => {
    const code = 'const uri = "mongodb://admin:password123@prod-server:27017/mydb";';
    const findings = secretsDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should not flag example credentials', () => {
    const code = 'const key = "your_api_key_here";';
    const findings = secretsDetector.detect(code, 'test.js', 'javascript');
    const apiKeyFindings = findings.filter(f => f.ruleId === 'SEC-GENERIC-API-KEY');
    expect(apiKeyFindings.length).toBe(0);
  });
});

describe('SSRF Detector', () => {
  it('should detect SSRF via user URL', () => {
    const code = 'fetch(req.query.url);';
    const findings = ssrfDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should not flag non-backend languages', () => {
    const code = 'fetch(req.query.url);';
    const findings = ssrfDetector.detect(code, 'test.html', 'html');
    expect(findings.length).toBe(0);
  });
});

describe('Path Traversal Detector', () => {
  it('should detect path traversal', () => {
    const code = 'fs.readFile(req.params.filename);';
    const findings = pathTraversalDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect directory traversal sequences', () => {
    const code = 'const path = "../../../etc/passwd";';
    const findings = pathTraversalDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('Prototype Pollution Detector', () => {
  it('should detect Object.assign merge', () => {
    const code = 'Object.assign(target, userInput);';
    const findings = prototypeDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should not flag non-JS languages', () => {
    const code = 'Object.assign(target, userInput);';
    const findings = prototypeDetector.detect(code, 'test.py', 'python');
    expect(findings.length).toBe(0);
  });
});

describe('Deserialization Detector', () => {
  it('should detect pickle.load in Python', () => {
    const code = 'data = pickle.load(file)';
    const findings = deserializeDetector.detect(code, 'test.py', 'python');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].severity).toBe(Severity.CRITICAL);
  });

  it('should detect Java ObjectInputStream', () => {
    const code = 'ObjectInputStream ois = new ObjectInputStream(input);';
    const findings = deserializeDetector.detect(code, 'Test.java', 'java');
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('Misconfiguration Detector', () => {
  it('should detect insecure cookies', () => {
    const code = '{ secure: false, httpOnly: false }';
    const findings = misconfigDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('should detect CORS wildcard', () => {
    const code = "cors({ origin: '*' })";
    const findings = misconfigDetector.detect(code, 'test.js', 'javascript');
    const corsFindings = findings.filter(f => f.ruleId.includes('CORS'));
    expect(corsFindings.length).toBeGreaterThan(0);
  });

  it('should detect nodeIntegration enabled', () => {
    const code = 'webPreferences: { nodeIntegration: true }';
    const findings = misconfigDetector.detect(code, 'test.js', 'javascript');
    expect(findings.length).toBeGreaterThan(0);
  });
});
