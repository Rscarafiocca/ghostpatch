import { Rule, Severity } from './severity';

const ALL_LANGS = ['javascript', 'typescript', 'python', 'java', 'go', 'rust', 'c', 'cpp', 'csharp', 'php', 'ruby', 'swift', 'kotlin', 'shell', 'sql'];
const WEB_LANGS = ['javascript', 'typescript', 'python', 'java', 'php', 'ruby', 'csharp', 'kotlin'];
const JS_TS = ['javascript', 'typescript'];
const BACKEND = ['javascript', 'typescript', 'python', 'java', 'go', 'php', 'ruby', 'csharp', 'kotlin'];

// ============================================================
// A01: Broken Access Control (CWE-284, CWE-639, CWE-862)
// ============================================================
const brokenAccessControl: Rule[] = [
  {
    id: 'BAC001', name: 'Missing Authentication Check', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-862', owasp: 'A01',
    pattern: /app\.(get|post|put|delete|patch)\s*\([^)]*(?:admin|user|account|profile|settings|dashboard)[^)]*,\s*(?!.*(?:auth|protect|guard|middleware|session|verify|check|require))/i,
    languages: JS_TS, description: 'Route handler for sensitive endpoint may lack authentication middleware.',
    remediation: 'Add authentication middleware before the route handler.',
  },
  {
    id: 'BAC002', name: 'Direct Object Reference', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-639', owasp: 'A01',
    pattern: /(?:params|query|body)\s*[\[.]\s*['"]?(?:id|userId|user_id|accountId|account_id|orderId)['"]?\s*[\])]?/i,
    antiPattern: /(?:authorize|ownership|belongs|verify.*owner|check.*permission)/i,
    languages: BACKEND, description: 'User-supplied ID used directly without ownership verification (IDOR risk).',
    remediation: 'Verify the authenticated user owns or has access to the requested resource.',
  },
  {
    id: 'BAC003', name: 'Unrestricted File Upload', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-434', owasp: 'A01',
    pattern: /(?:multer|upload|formidable|busboy|multipart)\s*\(/i,
    antiPattern: /(?:fileFilter|allowedTypes|whitelist|mimetype.*check|extension.*check|validateFile)/i,
    languages: JS_TS, description: 'File upload handler without apparent file type validation.',
    remediation: 'Validate file types, sizes, and content. Use allowlists for permitted extensions.',
  },
  {
    id: 'BAC004', name: 'CORS Wildcard', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-942', owasp: 'A01',
    pattern: /(?:Access-Control-Allow-Origin|cors\s*\()\s*[:(]\s*['"]?\*['"]?/i,
    languages: WEB_LANGS, description: 'CORS configured with wildcard origin, allowing any domain.',
    remediation: 'Restrict CORS to specific trusted origins.',
  },
  {
    id: 'BAC005', name: 'Missing CSRF Protection', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-352', owasp: 'A01',
    pattern: /app\.(post|put|delete|patch)\s*\(/i,
    antiPattern: /(?:csrf|xsrf|csurf|csrfProtection|_token|antiforgery)/i,
    languages: JS_TS, description: 'State-changing endpoint may lack CSRF protection.',
    remediation: 'Implement CSRF tokens or use SameSite cookie attribute.',
  },
  {
    id: 'BAC006', name: 'Privilege Escalation Risk', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-269', owasp: 'A01',
    pattern: /(?:role|isAdmin|is_admin|permission|privilege)\s*=\s*(?:req\.|request\.|params|body|query|input)/i,
    languages: BACKEND, description: 'User role or privilege set from user-controlled input.',
    remediation: 'Never derive authorization roles from user input. Use server-side session data.',
  },
  {
    id: 'BAC007', name: 'JWT None Algorithm', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-345', owasp: 'A01',
    pattern: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    languages: JS_TS, description: 'JWT configured to accept "none" algorithm, bypassing signature verification.',
    remediation: 'Never allow the "none" algorithm. Explicitly set allowed algorithms.',
  },
  {
    id: 'BAC008', name: 'Missing Authorization Decorator', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-862', owasp: 'A01',
    pattern: /@(?:Get|Post|Put|Delete|Patch)\s*\(/i,
    antiPattern: /(?:@Auth|@Authorize|@Guard|@Roles|@Permissions|@UseGuards|@Protected|@Public)/i,
    languages: ['typescript'], description: 'Controller endpoint may lack authorization decorator.',
    remediation: 'Add appropriate authorization guard or decorator.',
  },
  {
    id: 'BAC009', name: 'Insecure Redirect', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-601', owasp: 'A01',
    pattern: /(?:redirect|location)\s*[\(=]\s*(?:req\.|request\.|params|query|body|input)/i,
    languages: WEB_LANGS, description: 'Redirect URL taken from user input (open redirect vulnerability).',
    remediation: 'Validate redirect URLs against an allowlist of trusted destinations.',
  },
  {
    id: 'BAC010', name: 'Directory Listing Enabled', severity: Severity.LOW, confidence: 'high',
    cwe: 'CWE-548', owasp: 'A01',
    pattern: /(?:express\.static|serveStatic|autoindex\s+on|Options\s+\+?Indexes)/i,
    antiPattern: /(?:dotfiles.*deny|index.*false)/i,
    languages: [...JS_TS, 'shell'], description: 'Static file serving may expose directory listings.',
    remediation: 'Disable directory listing and serve only explicitly intended files.',
  },
];

// ============================================================
// A02: Cryptographic Failures (CWE-327, CWE-328, CWE-330)
// ============================================================
const cryptoFailures: Rule[] = [
  {
    id: 'CRYPTO001', name: 'Weak Hash Algorithm (MD5)', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-328', owasp: 'A02',
    pattern: /(?:md5|MD5)\s*[\(.<]/,
    languages: ALL_LANGS, description: 'MD5 is cryptographically broken and should not be used for security.',
    remediation: 'Use SHA-256 or stronger for integrity checks, bcrypt/scrypt/argon2 for passwords.',
  },
  {
    id: 'CRYPTO002', name: 'Weak Hash Algorithm (SHA1)', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-328', owasp: 'A02',
    pattern: /(?:sha1|SHA1|sha-1|SHA-1)\s*[\(.<'"]/,
    languages: ALL_LANGS, description: 'SHA-1 is deprecated for security use due to collision attacks.',
    remediation: 'Use SHA-256 or stronger.',
  },
  {
    id: 'CRYPTO003', name: 'Hardcoded Encryption Key', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-321', owasp: 'A02',
    pattern: /(?:(?:encryption|encrypt|cipher|aes|des|secret)[-_]?key|ENCRYPTION_KEY|SECRET_KEY)\s*[:=]\s*['"][^'"]{8,}['"]/i,
    languages: ALL_LANGS, description: 'Hardcoded encryption key found in source code.',
    remediation: 'Store encryption keys in environment variables or a key management service.',
  },
  {
    id: 'CRYPTO004', name: 'Weak Cipher (DES/RC4)', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-327', owasp: 'A02',
    pattern: /(?:createCipher(?:iv)?\s*\(\s*['"](?:des|rc4|rc2|blowfish)|DES(?:ede)?|RC4|Blowfish)\b/i,
    languages: ALL_LANGS, description: 'Weak or broken cipher algorithm detected.',
    remediation: 'Use AES-256-GCM or ChaCha20-Poly1305.',
  },
  {
    id: 'CRYPTO005', name: 'ECB Mode Encryption', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-327', owasp: 'A02',
    pattern: /(?:aes.*ecb|ECB|ecb.*mode|Mode\.ECB)/i,
    languages: ALL_LANGS, description: 'ECB mode does not provide semantic security.',
    remediation: 'Use GCM, CBC with HMAC, or another authenticated encryption mode.',
  },
  {
    id: 'CRYPTO006', name: 'Insecure Random Number', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-330', owasp: 'A02',
    pattern: /Math\.random\s*\(\)/,
    antiPattern: /(?:test|mock|sample|example|demo|shuffle|color|animation|ui|display|css)/i,
    languages: JS_TS, description: 'Math.random() is not cryptographically secure.',
    remediation: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive operations.',
  },
  {
    id: 'CRYPTO007', name: 'Insecure Random (Python)', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-330', owasp: 'A02',
    pattern: /(?:import\s+random|from\s+random\s+import|random\.(randint|choice|random|uniform|sample))/,
    antiPattern: /(?:test|mock|sample_data|example|seed)/i,
    languages: ['python'], description: 'Python random module is not cryptographically secure.',
    remediation: 'Use secrets module or os.urandom() for security-sensitive operations.',
  },
  {
    id: 'CRYPTO008', name: 'Missing HTTPS', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-319', owasp: 'A02',
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^'"]+['"]/,
    languages: ALL_LANGS, description: 'Unencrypted HTTP URL detected for non-local endpoint.',
    remediation: 'Use HTTPS for all external communications.',
  },
  {
    id: 'CRYPTO009', name: 'TLS Verification Disabled', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-295', owasp: 'A02',
    pattern: /(?:rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|SSL_VERIFY_NONE|check_hostname\s*=\s*False)/,
    languages: ALL_LANGS, description: 'TLS certificate verification disabled, vulnerable to MITM attacks.',
    remediation: 'Always verify TLS certificates in production.',
  },
  {
    id: 'CRYPTO010', name: 'Hardcoded IV/Nonce', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-329', owasp: 'A02',
    pattern: /(?:iv|nonce|IV|NONCE)\s*[:=]\s*(?:['"][^'"]{8,}['"]|Buffer\.from\s*\(\s*['"])/,
    languages: ALL_LANGS, description: 'Hardcoded initialization vector or nonce found.',
    remediation: 'Generate a unique random IV/nonce for each encryption operation.',
  },
  {
    id: 'CRYPTO011', name: 'Weak Password Hashing', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-916', owasp: 'A02',
    pattern: /(?:createHash\s*\(\s*['"](?:md5|sha1|sha256)['"]|hashlib\.(?:md5|sha1|sha256))\s*[(.]/,
    antiPattern: /(?:hmac|pbkdf2|checksum|file.*hash|integrity)/i,
    languages: [...JS_TS, 'python'], description: 'Plain hash used for password storage. Vulnerable to rainbow table attacks.',
    remediation: 'Use bcrypt, scrypt, or argon2 for password hashing.',
  },
  {
    id: 'CRYPTO012', name: 'Insufficient Key Length', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-326', owasp: 'A02',
    pattern: /(?:generateKeyPair|createRSAKey|RSA.*bits|keySize)\s*[:(]\s*(?:512|768|1024)\b/,
    languages: ALL_LANGS, description: 'RSA key length below recommended minimum of 2048 bits.',
    remediation: 'Use at least 2048-bit RSA keys, or prefer 4096-bit.',
  },
];

// ============================================================
// A03: Injection (CWE-79, CWE-89, CWE-78, CWE-90, CWE-917)
// ============================================================
const injection: Rule[] = [
  {
    id: 'INJ001', name: 'SQL Injection (String Concat)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:query|execute|exec|raw)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION)\s[^'"`]*['"`]\s*\+/i,
    languages: BACKEND, description: 'SQL query built with string concatenation — SQL injection risk.',
    remediation: 'Use parameterized queries or prepared statements.',
  },
  {
    id: 'INJ002', name: 'SQL Injection (Template Literal)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:query|execute|exec|raw)\s*\(\s*`(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s[^`]*\$\{/i,
    languages: JS_TS, description: 'SQL query built with template literals — SQL injection risk.',
    remediation: 'Use parameterized queries or prepared statements.',
  },
  {
    id: 'INJ003', name: 'SQL Injection (f-string)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:execute|cursor\.execute|fetchall|fetchone)\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE)\s/i,
    languages: ['python'], description: 'SQL query built with f-string — SQL injection risk.',
    remediation: 'Use parameterized queries with placeholders.',
  },
  {
    id: 'INJ004', name: 'SQL Injection (format)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:execute|cursor)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\s[^'"]*['"]\.format\s*\(/i,
    languages: ['python'], description: 'SQL query built with .format() — SQL injection risk.',
    remediation: 'Use parameterized queries with %s placeholders.',
  },
  {
    id: 'INJ005', name: 'Command Injection', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-78', owasp: 'A03',
    pattern: /(?:exec|execSync|spawn|spawnSync|execFile|child_process)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"\s]*\+\s*(?:req|input|param|arg|user|query|body))/i,
    languages: JS_TS, description: 'Command built with user input — OS command injection risk.',
    remediation: 'Use execFile with argument arrays. Never interpolate user input into commands.',
  },
  {
    id: 'INJ006', name: 'Command Injection (Python)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-78', owasp: 'A03',
    pattern: /(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*(?:f['"]|['"].*['"].*\+|.*\.format\s*\(|.*%\s)/,
    languages: ['python'], description: 'Command built with user input — OS command injection risk.',
    remediation: 'Use subprocess with shell=False and pass arguments as a list.',
  },
  {
    id: 'INJ007', name: 'XSS (innerHTML)', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-79', owasp: 'A03',
    pattern: /\.innerHTML\s*=\s*(?!['"]<(?:br|hr|p|div|span)\s*\/?>['"])/,
    languages: JS_TS, description: 'Setting innerHTML with dynamic content creates XSS risk.',
    remediation: 'Use textContent, or sanitize HTML with DOMPurify.',
  },
  {
    id: 'INJ008', name: 'XSS (document.write)', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-79', owasp: 'A03',
    pattern: /document\.write\s*\(/,
    languages: JS_TS, description: 'document.write can introduce XSS vulnerabilities.',
    remediation: 'Use DOM manipulation methods instead of document.write.',
  },
  {
    id: 'INJ009', name: 'XSS (dangerouslySetInnerHTML)', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-79', owasp: 'A03',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/,
    antiPattern: /(?:sanitize|purify|DOMPurify|xss|escape)/i,
    languages: JS_TS, description: 'React dangerouslySetInnerHTML used without sanitization.',
    remediation: 'Sanitize content with DOMPurify before using dangerouslySetInnerHTML.',
  },
  {
    id: 'INJ010', name: 'Eval Usage', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-95', owasp: 'A03',
    pattern: /\beval\s*\(\s*(?!['"][^'"]*['"])/,
    languages: [...JS_TS, 'python', 'php', 'ruby'], description: 'eval() with dynamic input enables code injection.',
    remediation: 'Avoid eval(). Use JSON.parse() for data, or safe alternatives.',
  },
  {
    id: 'INJ011', name: 'LDAP Injection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-90', owasp: 'A03',
    pattern: /(?:ldap|LDAP).*(?:search|bind|modify)\s*\(.*(?:\+|`|\$\{|\.format|%s)/,
    languages: BACKEND, description: 'LDAP query built with string concatenation — injection risk.',
    remediation: 'Use parameterized LDAP queries and escape special characters.',
  },
  {
    id: 'INJ012', name: 'NoSQL Injection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-943', owasp: 'A03',
    pattern: /(?:find|findOne|findMany|deleteOne|deleteMany|updateOne|updateMany|aggregate)\s*\(\s*(?:req\.body|req\.query|req\.params|request\.)/,
    languages: JS_TS, description: 'MongoDB query using unsanitized user input — NoSQL injection risk.',
    remediation: 'Validate and sanitize input. Use explicit field queries instead of passing raw input.',
  },
  {
    id: 'INJ013', name: 'Template Injection (SSTI)', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-1336', owasp: 'A03',
    pattern: /(?:render_template_string|Template\s*\(|Jinja2|nunjucks\.renderString|ejs\.render)\s*\(\s*(?:req|request|input|user|param|query|body)/i,
    languages: [...JS_TS, 'python'], description: 'User input used directly in template rendering — SSTI risk.',
    remediation: 'Never pass user input as template source. Use template files with data binding.',
  },
  {
    id: 'INJ014', name: 'XPath Injection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-643', owasp: 'A03',
    pattern: /(?:xpath|XPath|selectNodes?|evaluate)\s*\(.*(?:\+|`|\$\{|\.format)/,
    languages: BACKEND, description: 'XPath query built with string concatenation — injection risk.',
    remediation: 'Use parameterized XPath queries.',
  },
  {
    id: 'INJ015', name: 'RegExp Injection (ReDoS)', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-1333', owasp: 'A03',
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|request\.|input|user|param|query|body|arg)/i,
    languages: JS_TS, description: 'RegExp created from user input — ReDoS risk.',
    remediation: 'Validate and escape user input before using in RegExp, or use RE2.',
  },
  {
    id: 'INJ016', name: 'Header Injection', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-113', owasp: 'A03',
    pattern: /(?:setHeader|writeHead|header)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:req\.|request\.|input|user|param|query|body)/i,
    languages: WEB_LANGS, description: 'HTTP header value from user input — header injection risk.',
    remediation: 'Validate and sanitize values before setting HTTP headers.',
  },
  {
    id: 'INJ017', name: 'Code Injection (Function constructor)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-94', owasp: 'A03',
    pattern: /new\s+Function\s*\(\s*(?!['"][^'"]*['"]\s*\))/,
    languages: JS_TS, description: 'Function constructor with dynamic input is equivalent to eval().',
    remediation: 'Avoid the Function constructor. Use safe alternatives.',
  },
  {
    id: 'INJ018', name: 'Shell Injection via shell:true', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-78', owasp: 'A03',
    pattern: /(?:spawn|exec)\s*\([^)]*\{[^}]*shell\s*:\s*true/,
    languages: JS_TS, description: 'Using shell:true with spawn/exec enables shell injection.',
    remediation: 'Use spawn without shell:true, pass arguments as array.',
  },
];

// ============================================================
// A04: Insecure Design (CWE-209, CWE-256, CWE-501)
// ============================================================
const insecureDesign: Rule[] = [
  {
    id: 'DES001', name: 'Missing Rate Limiting', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-770', owasp: 'A04',
    pattern: /app\.(post|put)\s*\(\s*['"]\/(?:login|signin|auth|register|signup|password|reset|api\/token)['"]/i,
    antiPattern: /(?:rateLimit|rate-limit|throttle|brute|limiter)/i,
    languages: JS_TS, description: 'Authentication endpoint without apparent rate limiting.',
    remediation: 'Add rate limiting middleware (e.g., express-rate-limit) to auth endpoints.',
  },
  {
    id: 'DES002', name: 'Error Details Exposed', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-209', owasp: 'A04',
    pattern: /(?:res\.(?:send|json|status)\s*\(|response\.)\s*.*(?:err\.stack|error\.stack|stackTrace|stack_trace|traceback)/i,
    languages: WEB_LANGS, description: 'Stack trace or error details sent to client.',
    remediation: 'Log detailed errors server-side, return generic messages to clients.',
  },
  {
    id: 'DES003', name: 'Missing Input Validation', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-20', owasp: 'A04',
    pattern: /(?:req\.body|req\.query|req\.params)\s*\.\s*\w+/,
    antiPattern: /(?:validate|joi|yup|zod|express-validator|class-validator|sanitize|check\(|body\(|param\(|query\()/i,
    languages: JS_TS, description: 'Request input used without apparent validation.',
    remediation: 'Use input validation libraries like Joi, Zod, or express-validator.',
  },
  {
    id: 'DES004', name: 'Mass Assignment', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-915', owasp: 'A04',
    pattern: /(?:\.create|\.update|\.findAndUpdate|\.insertOne|Model\.)\s*\(\s*(?:req\.body|request\.body|\.\.\.req\.body|Object\.assign.*req\.body)/,
    languages: JS_TS, description: 'Entire request body passed to database operation — mass assignment risk.',
    remediation: 'Explicitly pick allowed fields from the request body.',
  },
  {
    id: 'DES005', name: 'Verbose Error Mode in Production', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-209', owasp: 'A04',
    pattern: /(?:DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV.*development|showStackError\s*:\s*true)/,
    antiPattern: /(?:process\.env|if\s*\(|test|spec|\.env\.example)/i,
    languages: ALL_LANGS, description: 'Debug/verbose error mode may be enabled in production.',
    remediation: 'Ensure debug mode is disabled in production environments.',
  },
  {
    id: 'DES006', name: 'Unrestricted Resource Consumption', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-400', owasp: 'A04',
    pattern: /(?:bodyParser\.json\(\s*\)|express\.json\(\s*\))/,
    antiPattern: /limit/,
    languages: JS_TS, description: 'JSON body parser without size limit — denial of service risk.',
    remediation: 'Set a body size limit: express.json({ limit: "100kb" })',
  },
  {
    id: 'DES007', name: 'Missing Timeout', severity: Severity.LOW, confidence: 'low',
    cwe: 'CWE-400', owasp: 'A04',
    pattern: /(?:fetch|axios|http\.request|urllib|requests\.(?:get|post)|HttpClient)\s*\(/,
    antiPattern: /(?:timeout|signal|AbortController)/i,
    languages: BACKEND, description: 'HTTP request without timeout configuration.',
    remediation: 'Always set timeouts on external HTTP requests.',
  },
];

// ============================================================
// A05: Security Misconfiguration (CWE-16, CWE-1004, CWE-614)
// ============================================================
const misconfig: Rule[] = [
  {
    id: 'CFG001', name: 'Debug Mode Enabled', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-489', owasp: 'A05',
    pattern: /(?:app\.debug\s*=\s*True|DEBUG\s*=\s*True|debug:\s*true|EnableDebugging|SetDebug\(true\))/,
    antiPattern: /(?:process\.env|os\.environ|config\.get|if\s|\.env)/,
    languages: ALL_LANGS, description: 'Application debug mode appears to be hardcoded as enabled.',
    remediation: 'Use environment variable for debug mode, ensure disabled in production.',
  },
  {
    id: 'CFG002', name: 'Default Credentials', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A05',
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"](?:admin|password|123456|root|default|test|guest|letmein|welcome|monkey|dragon|master|qwerty|abc123)['"]/i,
    languages: ALL_LANGS, description: 'Default or common password found in source code.',
    remediation: 'Remove hardcoded credentials. Use environment variables or secret management.',
  },
  {
    id: 'CFG003', name: 'Insecure Cookie', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-614', owasp: 'A05',
    pattern: /(?:secure\s*:\s*false|httpOnly\s*:\s*false|sameSite\s*:\s*['"]?none['"]?)/i,
    languages: JS_TS, description: 'Cookie configured with insecure flags.',
    remediation: 'Set secure: true, httpOnly: true, sameSite: "strict" for session cookies.',
  },
  {
    id: 'CFG004', name: 'Missing Security Headers', severity: Severity.LOW, confidence: 'low',
    cwe: 'CWE-693', owasp: 'A05',
    pattern: /(?:app\.listen|createServer|express\(\))/,
    antiPattern: /(?:helmet|security.*header|X-Content-Type|X-Frame-Options|Content-Security-Policy|Strict-Transport|csp)/i,
    languages: JS_TS, description: 'Web server may lack security headers.',
    remediation: 'Use Helmet.js or manually set security headers (CSP, HSTS, X-Frame-Options).',
  },
  {
    id: 'CFG005', name: 'Exposed GraphQL Introspection', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-200', owasp: 'A05',
    pattern: /introspection\s*:\s*true/,
    languages: JS_TS, description: 'GraphQL introspection enabled — schema exposed to attackers.',
    remediation: 'Disable introspection in production.',
  },
  {
    id: 'CFG006', name: 'Exposed .env File', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-538', owasp: 'A05',
    pattern: /express\.static\s*\(\s*['"]\.?\/?['"]\s*\)|serveStatic\s*\(\s*['"]\.?\/?['"]/,
    languages: JS_TS, description: 'Serving files from root directory may expose .env and other sensitive files.',
    remediation: 'Serve static files from a dedicated public directory.',
  },
  {
    id: 'CFG007', name: 'Wildcard CORS Origin', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-942', owasp: 'A05',
    pattern: /origin\s*:\s*(?:true|['"]?\*['"]?|\(\s*_\s*,\s*callback\s*\)\s*=>\s*callback\s*\(\s*null\s*,\s*true\s*\))/,
    languages: JS_TS, description: 'CORS allows all origins, enabling cross-origin attacks.',
    remediation: 'Restrict CORS to specific trusted origins.',
  },
  {
    id: 'CFG008', name: 'Verbose Server Banner', severity: Severity.LOW, confidence: 'medium',
    cwe: 'CWE-200', owasp: 'A05',
    pattern: /(?:x-powered-by|server:\s|Server:\s|expose_php)/i,
    antiPattern: /(?:disable|remove|false|off)/i,
    languages: ALL_LANGS, description: 'Server version information may be exposed in headers.',
    remediation: 'Remove or disable server identification headers.',
  },
  {
    id: 'CFG009', name: 'Permissive File Permissions', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-732', owasp: 'A05',
    pattern: /(?:chmod\s+(?:777|666|755.*sensitive)|os\.chmod.*0o?777|writeFile.*mode.*0o?777)/,
    languages: ALL_LANGS, description: 'Overly permissive file permissions (world-writable).',
    remediation: 'Use restrictive permissions. Files: 644, directories: 755, secrets: 600.',
  },
  {
    id: 'CFG010', name: 'Binding to All Interfaces', severity: Severity.LOW, confidence: 'medium',
    cwe: 'CWE-668', owasp: 'A05',
    pattern: /(?:listen\s*\(\s*(?:\d+\s*,\s*)?['"]0\.0\.0\.0['"]|host\s*[:=]\s*['"]0\.0\.0\.0['"]|INADDR_ANY)/,
    languages: ALL_LANGS, description: 'Server binding to all network interfaces.',
    remediation: 'Bind to localhost (127.0.0.1) in development. Use firewall rules in production.',
  },
];

// ============================================================
// A06: Vulnerable Components (CWE-1035, CWE-1104)
// ============================================================
const vulnerableComponents: Rule[] = [
  {
    id: 'DEP001', name: 'Known Vulnerable Package (lodash)', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-1035', owasp: 'A06',
    pattern: /['"]lodash['"]\s*:\s*['"][^'"]*(?:^[0-3]\.|4\.(?:0|1[0-6])\.)/,
    languages: ALL_LANGS, description: 'Potentially outdated lodash version with known prototype pollution vulnerabilities.',
    remediation: 'Update to latest lodash version.',
  },
  {
    id: 'DEP002', name: 'Known Vulnerable Package (jQuery)', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-1035', owasp: 'A06',
    pattern: /(?:jquery.*(?:1\.\d|2\.[012])|cdn.*jquery.*(?:1\.\d|2\.[012]))/i,
    languages: [...JS_TS, 'html'], description: 'Outdated jQuery version with known XSS vulnerabilities.',
    remediation: 'Update to jQuery 3.5+ or remove jQuery dependency.',
  },
  {
    id: 'DEP003', name: 'Pinned to Vulnerable Version', severity: Severity.LOW, confidence: 'low',
    cwe: 'CWE-1104', owasp: 'A06',
    pattern: /['"](?:express|axios|socket\.io|mongoose|sequelize)['"]\s*:\s*['"]\d+\.\d+\.\d+['"]/,
    languages: ALL_LANGS, description: 'Dependency pinned to exact version — may miss security patches.',
    remediation: 'Use caret (^) or tilde (~) version ranges to receive patch updates.',
  },
];

// ============================================================
// A07: Authentication Failures (CWE-287, CWE-256, CWE-521)
// ============================================================
const authFailures: Rule[] = [
  {
    id: 'AUTH001', name: 'Weak Password Policy', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-521', owasp: 'A07',
    pattern: /(?:password|passwd).*(?:length|len|min).*(?:[1-5]|minLength\s*[:=]\s*[1-5])\b/i,
    languages: ALL_LANGS, description: 'Password minimum length too short (should be 8+ characters).',
    remediation: 'Enforce minimum 8-character passwords with complexity requirements.',
  },
  {
    id: 'AUTH002', name: 'Missing Password Hashing', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-256', owasp: 'A07',
    pattern: /(?:password|passwd)\s*[:=]\s*(?:req\.|request\.|input|body)\.[^;]*(?:save|create|insert|update)\s*\(/i,
    antiPattern: /(?:hash|bcrypt|scrypt|argon|pbkdf|encrypt|crypt)/i,
    languages: BACKEND, description: 'Password appears to be stored without hashing.',
    remediation: 'Hash passwords with bcrypt, scrypt, or argon2 before storage.',
  },
  {
    id: 'AUTH003', name: 'Hardcoded JWT Secret', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A07',
    pattern: /(?:jwt|jsonwebtoken)\.(?:sign|verify)\s*\([^)]*,\s*['"][^'"]{4,}['"]/i,
    languages: JS_TS, description: 'JWT secret hardcoded in source code.',
    remediation: 'Store JWT secret in environment variable.',
  },
  {
    id: 'AUTH004', name: 'JWT Without Expiration', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-613', owasp: 'A07',
    pattern: /jwt\.sign\s*\(\s*\{[^}]*\}\s*,/,
    antiPattern: /(?:expiresIn|exp:|maxAge)/i,
    languages: JS_TS, description: 'JWT token created without expiration time.',
    remediation: 'Always set token expiration with expiresIn option.',
  },
  {
    id: 'AUTH005', name: 'Session Fixation', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-384', owasp: 'A07',
    pattern: /(?:login|authenticate|signIn)\s*(?:=|:).*\{/i,
    antiPattern: /(?:regenerate|destroy.*session|req\.session\.regenerate|session\.invalidate)/i,
    languages: WEB_LANGS, description: 'Login handler may not regenerate session ID — session fixation risk.',
    remediation: 'Regenerate session ID after successful authentication.',
  },
  {
    id: 'AUTH006', name: 'Plaintext Password in URL', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-598', owasp: 'A07',
    pattern: /(?:url|href|redirect|link).*[?&](?:password|passwd|pwd|secret|token)=/i,
    languages: ALL_LANGS, description: 'Sensitive data passed in URL query parameters.',
    remediation: 'Send sensitive data in request body or headers, never in URLs.',
  },
  {
    id: 'AUTH007', name: 'Missing Account Lockout', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-307', owasp: 'A07',
    pattern: /(?:login|authenticate|signIn|signin)\s*(?:=|:|\().*(?:password|credential)/i,
    antiPattern: /(?:lockout|maxAttempts|max_attempts|failedAttempts|failed_attempts|brute|throttle|rateLimit)/i,
    languages: BACKEND, description: 'Login function without apparent brute force protection.',
    remediation: 'Implement account lockout or progressive delays after failed attempts.',
  },
  {
    id: 'AUTH008', name: 'Insecure Remember Me', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-613', owasp: 'A07',
    pattern: /(?:remember.*me|rememberMe|keep.*logged|persistent.*session).*(?:cookie|token)/i,
    antiPattern: /(?:secure|httpOnly|signed|encrypted)/i,
    languages: WEB_LANGS, description: 'Remember-me functionality may use insecure token storage.',
    remediation: 'Use secure, httpOnly, signed tokens for persistent sessions.',
  },
];

// ============================================================
// A08: Data Integrity Failures (CWE-502, CWE-829)
// ============================================================
const dataIntegrity: Rule[] = [
  {
    id: 'SER001', name: 'Insecure Deserialization (JS)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-502', owasp: 'A08',
    pattern: /(?:serialize|node-serialize|js-yaml\.load(?!.*safe)|unserialize|phpunserialize)\s*\(/i,
    languages: [...JS_TS, 'php'], description: 'Insecure deserialization of potentially untrusted data.',
    remediation: 'Use safe deserialization methods (js-yaml.safeLoad, JSON.parse for data).',
  },
  {
    id: 'SER002', name: 'Insecure Deserialization (Python)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-502', owasp: 'A08',
    pattern: /(?:pickle\.loads?|yaml\.(?:load|unsafe_load)|marshal\.loads?|shelve\.open)\s*\(/,
    antiPattern: /(?:safe_load|SafeLoader|Loader=yaml\.SafeLoader)/,
    languages: ['python'], description: 'Insecure deserialization — arbitrary code execution risk.',
    remediation: 'Use yaml.safe_load(), avoid pickle for untrusted data, use JSON.',
  },
  {
    id: 'SER003', name: 'Insecure Deserialization (Java)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-502', owasp: 'A08',
    pattern: /(?:ObjectInputStream|readObject|XMLDecoder|XStream|Kryo|Hessian)\s*[\.(]/,
    languages: ['java', 'kotlin'], description: 'Java deserialization of potentially untrusted data.',
    remediation: 'Use allowlist-based deserialization filter or avoid native serialization.',
  },
  {
    id: 'SER004', name: 'Untrusted CDN/Script', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-829', owasp: 'A08',
    pattern: /<script\s+src\s*=\s*['"]https?:\/\/(?!(?:cdn\.jsdelivr|cdnjs\.cloudflare|unpkg|ajax\.googleapis))/i,
    antiPattern: /integrity\s*=/i,
    languages: ['html'], description: 'External script loaded without Subresource Integrity (SRI).',
    remediation: 'Add integrity and crossorigin attributes to external script tags.',
  },
];

// ============================================================
// A09: Security Logging & Monitoring Failures (CWE-778)
// ============================================================
const loggingFailures: Rule[] = [
  {
    id: 'LOG001', name: 'Sensitive Data in Logs', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-532', owasp: 'A09',
    pattern: /(?:console\.log|logger?\.\w+|print|println|System\.out|logging\.\w+)\s*\([^)]*(?:password|passwd|secret|token|apiKey|api_key|credit.?card|ssn|social.?security)[^)]*\)/i,
    languages: ALL_LANGS, description: 'Sensitive data may be written to logs.',
    remediation: 'Mask or redact sensitive data before logging.',
  },
  {
    id: 'LOG002', name: 'Log Injection', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-117', owasp: 'A09',
    pattern: /(?:console\.log|logger?\.\w+|logging\.\w+)\s*\(\s*(?:`[^`]*\$\{(?:req|request|input|user)|['"][^'"]*['"]\s*\+\s*(?:req|request|input|user))/i,
    languages: BACKEND, description: 'User input written to logs without sanitization — log injection risk.',
    remediation: 'Sanitize user input before logging. Remove newlines and control characters.',
  },
  {
    id: 'LOG003', name: 'Console.log in Production', severity: Severity.LOW, confidence: 'low',
    cwe: 'CWE-489', owasp: 'A09',
    pattern: /console\.(?:log|debug|trace)\s*\(/,
    antiPattern: /(?:test|spec|debug|dev|\.test\.|\.spec\.|__test)/i,
    languages: JS_TS, description: 'Console.log statements may leak information in production.',
    remediation: 'Use a proper logging library with level control.',
  },
];

// ============================================================
// A10: Server-Side Request Forgery (CWE-918)
// ============================================================
const ssrf: Rule[] = [
  {
    id: 'SSRF001', name: 'SSRF via User URL', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-918', owasp: 'A10',
    pattern: /(?:fetch|axios|http\.get|https\.get|request|urllib|requests\.get|HttpClient\.get)\s*\(\s*(?:req\.|request\.|input|user|param|query|body|arg|url|uri)/i,
    languages: BACKEND, description: 'HTTP request URL from user input — SSRF risk.',
    remediation: 'Validate and allowlist URLs. Block internal/private IP ranges.',
  },
  {
    id: 'SSRF002', name: 'DNS Rebinding Risk', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-918', owasp: 'A10',
    pattern: /(?:fetch|axios|request)\s*\(\s*(?:url|uri|endpoint|target|destination)\s*[,)]/i,
    antiPattern: /(?:allowlist|whitelist|validateUrl|isAllowed|checkUrl|blockPrivate)/i,
    languages: BACKEND, description: 'HTTP request to variable URL without apparent validation.',
    remediation: 'Validate URL and resolved IP against allowlist. Check for DNS rebinding.',
  },
];

// ============================================================
// Additional: Secrets & Hardcoded Credentials
// ============================================================
const secrets: Rule[] = [
  {
    id: 'SEC001', name: 'AWS Access Key', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/,
    antiPattern: /(?:example|sample|test|fake|dummy|placeholder|xxx|your_)/i,
    languages: ALL_LANGS, description: 'AWS access key ID found in source code.',
    remediation: 'Remove the key and rotate it immediately. Use IAM roles or environment variables.',
  },
  {
    id: 'SEC002', name: 'AWS Secret Key', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]/,
    languages: ALL_LANGS, description: 'AWS secret access key found in source code.',
    remediation: 'Remove and rotate immediately. Use IAM roles or AWS Secrets Manager.',
  },
  {
    id: 'SEC003', name: 'Generic API Key', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:api[-_]?key|apikey|API[-_]?KEY)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/i,
    antiPattern: /(?:example|sample|test|fake|dummy|placeholder|xxx|your_|process\.env|os\.environ|config\.|env\[)/i,
    languages: ALL_LANGS, description: 'Hardcoded API key found in source code.',
    remediation: 'Store API keys in environment variables or a secrets manager.',
  },
  {
    id: 'SEC004', name: 'Private Key', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-321', owasp: 'A02',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
    languages: ALL_LANGS, description: 'Private key embedded in source code.',
    remediation: 'Remove private key from source. Use file references or key management service.',
  },
  {
    id: 'SEC005', name: 'GitHub Token', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    languages: ALL_LANGS, description: 'GitHub personal access token found in source code.',
    remediation: 'Remove and rotate the token immediately. Use environment variables.',
  },
  {
    id: 'SEC006', name: 'Google API Key', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /AIza[A-Za-z0-9_\\-]{35}/,
    languages: ALL_LANGS, description: 'Google API key found in source code.',
    remediation: 'Remove and rotate the key. Use environment variables and restrict key scope.',
  },
  {
    id: 'SEC007', name: 'Slack Token', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /xox[bpors]-[A-Za-z0-9-]{10,}/,
    languages: ALL_LANGS, description: 'Slack API token found in source code.',
    remediation: 'Remove and rotate immediately. Use environment variables.',
  },
  {
    id: 'SEC008', name: 'Stripe Key', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/,
    languages: ALL_LANGS, description: 'Stripe API key found in source code.',
    remediation: 'Remove and rotate immediately. Use environment variables.',
  },
  {
    id: 'SEC009', name: 'Generic Secret', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:secret|SECRET|token|TOKEN|password|PASSWORD|passwd|PASSWD|credentials?|CREDENTIALS?)\s*[:=]\s*['"][a-zA-Z0-9!@#$%^&*()_+\-={}\[\]:;"'<>,.?/\\|~`]{12,}['"]/,
    antiPattern: /(?:example|sample|test|fake|dummy|placeholder|xxx|your_|process\.env|os\.environ|config\.|env\[|<|TODO|CHANGE|REPLACE)/i,
    languages: ALL_LANGS, description: 'Potential hardcoded secret or credential found.',
    remediation: 'Store secrets in environment variables or a secrets manager.',
  },
  {
    id: 'SEC010', name: 'Database Connection String', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /['"](?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mssql|redis|amqp):\/\/[^:]+:[^@]+@[^'"]+['"]/i,
    antiPattern: /(?:localhost|127\.0\.0\.1|example\.com|process\.env|os\.environ)/i,
    languages: ALL_LANGS, description: 'Database connection string with credentials in source code.',
    remediation: 'Use environment variables for database connection strings.',
  },
  {
    id: 'SEC011', name: 'SendGrid API Key', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/,
    languages: ALL_LANGS, description: 'SendGrid API key found in source code.',
    remediation: 'Remove and rotate immediately. Use environment variables.',
  },
  {
    id: 'SEC012', name: 'Twilio Credentials', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:AC[a-z0-9]{32}|SK[a-z0-9]{32})/,
    languages: ALL_LANGS, description: 'Twilio Account SID or API key found in source code.',
    remediation: 'Remove and rotate immediately. Use environment variables.',
  },
  {
    id: 'SEC013', name: 'Heroku API Key', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:heroku.*api[-_]?key|HEROKU_API_KEY)\s*[:=]\s*['"][a-f0-9-]{36,}['"]/i,
    languages: ALL_LANGS, description: 'Heroku API key found in source code.',
    remediation: 'Remove and rotate immediately. Use environment variables.',
  },
  {
    id: 'SEC014', name: 'Firebase Config', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-798', owasp: 'A02',
    pattern: /(?:firebase|FIREBASE).*(?:apiKey|authDomain|databaseURL|storageBucket)\s*[:=]\s*['"]/i,
    languages: ALL_LANGS, description: 'Firebase configuration found in source code.',
    remediation: 'Use environment variables for Firebase config. Secure with Firebase Security Rules.',
  },
];

// ============================================================
// Prototype Pollution (JavaScript specific)
// ============================================================
const prototypePollution: Rule[] = [
  {
    id: 'PROTO001', name: 'Prototype Pollution via Merge', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-1321', owasp: 'A03',
    pattern: /(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep|deepmerge|deep-extend|merge-deep)\s*\(\s*(?:\{\}|target|dst|obj)/,
    languages: JS_TS, description: 'Deep merge operation may be vulnerable to prototype pollution.',
    remediation: 'Validate input keys. Reject __proto__, constructor, and prototype.',
  },
  {
    id: 'PROTO002', name: 'Prototype Pollution via Bracket Notation', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-1321', owasp: 'A03',
    pattern: /\w+\s*\[\s*(?:key|prop|name|field|attr|k|p)\s*\]\s*=\s*(?!undefined|null|false|true|0|''|"")/,
    antiPattern: /(?:hasOwnProperty|Object\.keys|Object\.entries|whitelist|allowlist|sanitize|prototype|__proto__|constructor)/i,
    languages: JS_TS, description: 'Dynamic property assignment without prototype pollution check.',
    remediation: 'Check that key is not __proto__, constructor, or prototype before assignment.',
  },
];

// ============================================================
// Path Traversal (CWE-22)
// ============================================================
const pathTraversal: Rule[] = [
  {
    id: 'PATH001', name: 'Path Traversal', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-22', owasp: 'A01',
    pattern: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|open|openSync)\s*\(\s*(?:req\.|request\.|input|user|param|query|body|path\.join\s*\([^)]*req)/i,
    languages: JS_TS, description: 'File operation with user-controlled path — directory traversal risk.',
    remediation: 'Validate and sanitize file paths. Use path.resolve() and check against base directory.',
  },
  {
    id: 'PATH002', name: 'Path Traversal (Python)', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-22', owasp: 'A01',
    pattern: /(?:open|os\.path\.join|pathlib\.Path)\s*\(\s*(?:request\.|input|user_|flask\.request|args\.get)/i,
    languages: ['python'], description: 'File operation with user-controlled path — directory traversal risk.',
    remediation: 'Validate paths against a safe base directory. Use os.path.realpath() to resolve symlinks.',
  },
  {
    id: 'PATH003', name: 'Zip Slip', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-22', owasp: 'A01',
    pattern: /(?:extractAll|extract\s*\(|unzip|ZipFile|tar\.extractall|tar\.extract)\s*\(/i,
    antiPattern: /(?:validatePath|sanitize|startsWith|normalize|realpath|abspath)/i,
    languages: BACKEND, description: 'Archive extraction without path validation — Zip Slip vulnerability.',
    remediation: 'Validate extracted file paths stay within the intended directory.',
  },
];

// ============================================================
// Additional patterns for comprehensive coverage
// ============================================================
const additional: Rule[] = [
  {
    id: 'MISC001', name: 'setTimeout/setInterval with String', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-95', owasp: 'A03',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*['"`]/,
    languages: JS_TS, description: 'setTimeout/setInterval with string argument acts like eval().',
    remediation: 'Pass a function reference instead of a string.',
  },
  {
    id: 'MISC002', name: 'Unsafe Reflection', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-470', owasp: 'A03',
    pattern: /(?:require\s*\(|import\s*\()\s*(?:req\.|request\.|input|user|param|query|body)/i,
    languages: JS_TS, description: 'Dynamic require/import with user input — code injection risk.',
    remediation: 'Use a mapping of allowed module names instead of dynamic import.',
  },
  {
    id: 'MISC003', name: 'XML External Entity (XXE)', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-611', owasp: 'A05',
    pattern: /(?:parseXML|xml2js|DOMParser|SAXParser|XMLReader|etree\.parse|lxml\.etree)\s*[(.]/i,
    antiPattern: /(?:disallow.*dtd|external.*entity.*false|FEATURE_EXTERNAL|resolve_entities\s*=\s*False)/i,
    languages: BACKEND, description: 'XML parsing without apparent XXE protection.',
    remediation: 'Disable DTD processing and external entity resolution.',
  },
  {
    id: 'MISC004', name: 'Hardcoded IP Address', severity: Severity.LOW, confidence: 'medium',
    cwe: 'CWE-798', owasp: 'A05',
    pattern: /['"](?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})['"]/,
    languages: ALL_LANGS, description: 'Hardcoded private IP address found in source code.',
    remediation: 'Use configuration files or environment variables for IP addresses.',
  },
  {
    id: 'MISC005', name: 'Unsafe YAML Loading', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-502', owasp: 'A08',
    pattern: /yaml\.load\s*\(/,
    antiPattern: /(?:safe_load|SafeLoader|Loader\s*=\s*yaml\.SafeLoader)/,
    languages: ['python'], description: 'yaml.load() without SafeLoader enables code execution.',
    remediation: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
  },
  {
    id: 'MISC006', name: 'Process Environment Exposure', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-200', owasp: 'A05',
    pattern: /(?:res\.(?:send|json)|response\.)\s*\(\s*process\.env\s*\)/,
    languages: JS_TS, description: 'Entire process.env sent to client, exposing all environment variables.',
    remediation: 'Only send specific, non-sensitive configuration values to the client.',
  },
  {
    id: 'MISC007', name: 'Disabled Security Feature', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-693', owasp: 'A05',
    pattern: /(?:helmet\.(?:contentSecurityPolicy|hsts|frameguard)\s*\(\s*\{\s*(?:enable|enabled)\s*:\s*false|app\.disable\s*\(\s*['"]x-powered-by['"])/,
    languages: JS_TS, description: 'Security feature explicitly disabled.',
    remediation: 'Re-enable security features or document the specific reason for disabling.',
  },
  {
    id: 'MISC008', name: 'Potential Timing Attack', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-208', owasp: 'A02',
    pattern: /(?:===?\s*(?:password|token|secret|apiKey|hash)|(?:password|token|secret|apiKey|hash)\s*===?)/i,
    antiPattern: /(?:timingSafe|crypto\.timingSafeEqual|constantTime|hmac\.compare|secrets\.compare_digest)/i,
    languages: BACKEND, description: 'String comparison of secrets vulnerable to timing attacks.',
    remediation: 'Use crypto.timingSafeEqual() or constant-time comparison for secrets.',
  },
  {
    id: 'MISC009', name: 'Unvalidated Redirect URL', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-601', owasp: 'A01',
    pattern: /(?:redirect|302|301|location)\s*[\(=:]\s*(?:req\.query|request\.args|params\[|searchParams)/i,
    languages: WEB_LANGS, description: 'Redirect destination from query parameter — open redirect risk.',
    remediation: 'Validate redirect URLs against an allowlist of trusted paths/domains.',
  },
  {
    id: 'MISC010', name: 'Electron Node Integration', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-94', owasp: 'A03',
    pattern: /nodeIntegration\s*:\s*true/,
    languages: JS_TS, description: 'Electron nodeIntegration enabled — XSS can lead to RCE.',
    remediation: 'Disable nodeIntegration and use contextBridge for IPC.',
  },
  {
    id: 'MISC011', name: 'Electron Context Isolation Disabled', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-94', owasp: 'A03',
    pattern: /contextIsolation\s*:\s*false/,
    languages: JS_TS, description: 'Electron contextIsolation disabled — preload scripts can be exploited.',
    remediation: 'Enable contextIsolation and use contextBridge.',
  },
  {
    id: 'MISC012', name: 'postMessage Without Origin Check', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-346', owasp: 'A01',
    pattern: /addEventListener\s*\(\s*['"]message['"]/,
    antiPattern: /(?:origin|source)/i,
    languages: JS_TS, description: 'postMessage event handler without origin validation.',
    remediation: 'Always verify event.origin before processing postMessage data.',
  },
  {
    id: 'MISC013', name: 'Unsafe innerHTML Assignment', severity: Severity.HIGH, confidence: 'high',
    cwe: 'CWE-79', owasp: 'A03',
    pattern: /\.(?:outerHTML|insertAdjacentHTML)\s*(?:=|\()\s*/,
    languages: JS_TS, description: 'Unsafe HTML insertion that may lead to XSS.',
    remediation: 'Use textContent or sanitize HTML before insertion.',
  },
  {
    id: 'MISC014', name: 'Unsafe window.open', severity: Severity.LOW, confidence: 'medium',
    cwe: 'CWE-1022', owasp: 'A01',
    pattern: /window\.open\s*\(/,
    antiPattern: /(?:noopener|noreferrer)/,
    languages: JS_TS, description: 'window.open without noopener/noreferrer — reverse tabnabbing risk.',
    remediation: 'Add "noopener,noreferrer" to window.open features.',
  },
  {
    id: 'MISC015', name: 'Race Condition (TOCTOU)', severity: Severity.MEDIUM, confidence: 'low',
    cwe: 'CWE-367', owasp: 'A04',
    pattern: /(?:fs\.(?:exists|access|stat)(?:Sync)?\s*\([^)]+\)[^;]*(?:fs\.(?:read|write|unlink|mkdir|rmdir)|os\.path\.exists|os\.access))/,
    languages: [...JS_TS, 'python'], description: 'Time-of-check to time-of-use file operation race condition.',
    remediation: 'Use atomic file operations or file locking.',
  },
  {
    id: 'MISC016', name: 'Exposed Docker Socket', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-250', owasp: 'A05',
    pattern: /(?:\/var\/run\/docker\.sock|docker\.sock|DOCKER_HOST.*tcp:\/\/)/,
    languages: ALL_LANGS, description: 'Docker socket access — container escape risk.',
    remediation: 'Restrict Docker socket access. Use rootless Docker or Podman.',
  },
  {
    id: 'MISC017', name: 'Kubernetes Secrets in Env', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-798', owasp: 'A05',
    pattern: /(?:secretKeyRef|valueFrom.*secretKeyRef|kind:\s*Secret)/,
    languages: ALL_LANGS, description: 'Kubernetes secrets may be exposed in environment variables.',
    remediation: 'Use mounted volumes for secrets, enable encryption at rest.',
  },
  {
    id: 'MISC018', name: 'SQL Injection (Java)', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:Statement|createStatement|executeQuery|executeUpdate)\s*\(?\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s[^'"]*['"]\s*\+/i,
    languages: ['java', 'kotlin'], description: 'SQL query built with string concatenation in Java.',
    remediation: 'Use PreparedStatement with parameterized queries.',
  },
  {
    id: 'MISC019', name: 'Go SQL Injection', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:db\.(?:Query|Exec|QueryRow))\s*\(\s*(?:fmt\.Sprintf|"[^"]*"\s*\+)/,
    languages: ['go'], description: 'SQL query built with string formatting in Go.',
    remediation: 'Use parameterized queries with $1, $2 placeholders.',
  },
  {
    id: 'MISC020', name: 'PHP SQL Injection', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-89', owasp: 'A03',
    pattern: /(?:mysql_query|mysqli_query|pg_query)\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE)\s[^'"]*['"]\s*\.\s*\$/i,
    languages: ['php'], description: 'SQL query built with string concatenation in PHP.',
    remediation: 'Use PDO prepared statements.',
  },
  {
    id: 'MISC021', name: 'PHP Command Injection', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-78', owasp: 'A03',
    pattern: /(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$(?!_SERVER)/,
    languages: ['php'], description: 'PHP command execution with variable input.',
    remediation: 'Use escapeshellarg() and escapeshellcmd() for any user input.',
  },
  {
    id: 'MISC022', name: 'Ruby Command Injection', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-78', owasp: 'A03',
    pattern: /(?:system|exec|`|\%x)\s*[\(\[{]?\s*(?:#\{|['"].*['"].*\+)/,
    languages: ['ruby'], description: 'Ruby command execution with interpolated input.',
    remediation: 'Use array form of system() or Open3 module.',
  },
  {
    id: 'MISC023', name: 'Insufficient Entropy', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-331', owasp: 'A02',
    pattern: /(?:uuid|token|session|nonce|salt)\s*[:=]\s*(?:Date\.now|time\.time|System\.currentTimeMillis|Time\.now)/i,
    languages: ALL_LANGS, description: 'Using timestamp for security-sensitive value — insufficient entropy.',
    remediation: 'Use cryptographically secure random number generator.',
  },
  {
    id: 'MISC024', name: 'Missing Content-Type Validation', severity: Severity.LOW, confidence: 'low',
    cwe: 'CWE-20', owasp: 'A04',
    pattern: /(?:app\.(?:post|put|patch)|router\.(?:post|put|patch))\s*\(/i,
    antiPattern: /(?:content-type|Content-Type|bodyParser|express\.json|express\.urlencoded|multer)/i,
    languages: JS_TS, description: 'Endpoint may not validate Content-Type header.',
    remediation: 'Validate Content-Type headers for incoming requests.',
  },
  {
    id: 'MISC025', name: 'Unsafe Object Spread from User Input', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-915', owasp: 'A04',
    pattern: /\{\s*\.\.\.(?:req\.body|req\.query|request\.body|request\.data)/,
    languages: JS_TS, description: 'Spreading user input into objects — mass assignment risk.',
    remediation: 'Explicitly destructure only the fields you expect.',
  },
  {
    id: 'MISC026', name: 'C/C++ Buffer Overflow', severity: Severity.CRITICAL, confidence: 'medium',
    cwe: 'CWE-120', owasp: 'A03',
    pattern: /(?:strcpy|strcat|sprintf|gets|scanf)\s*\(/,
    languages: ['c', 'cpp'], description: 'Unsafe C function prone to buffer overflow.',
    remediation: 'Use strncpy, strncat, snprintf, fgets, or sscanf with size limits.',
  },
  {
    id: 'MISC027', name: 'C/C++ Format String', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-134', owasp: 'A03',
    pattern: /(?:printf|fprintf|sprintf|syslog)\s*\(\s*(?!['"][^'"]*['"])[a-zA-Z_]\w*\s*\)/,
    languages: ['c', 'cpp'], description: 'Format string vulnerability — variable used as format string.',
    remediation: 'Always use a literal format string: printf("%s", variable).',
  },
  {
    id: 'MISC028', name: 'C/C++ Use After Free Risk', severity: Severity.HIGH, confidence: 'low',
    cwe: 'CWE-416', owasp: 'A08',
    pattern: /free\s*\(\s*(\w+)\s*\)\s*;(?!.*\1\s*=\s*NULL)/,
    languages: ['c', 'cpp'], description: 'Pointer not nullified after free — use-after-free risk.',
    remediation: 'Set pointer to NULL after freeing.',
  },
  {
    id: 'MISC029', name: 'Go Unsafe Package', severity: Severity.MEDIUM, confidence: 'high',
    cwe: 'CWE-242', owasp: 'A04',
    pattern: /import\s+['"]unsafe['"]/,
    languages: ['go'], description: 'Go unsafe package used — bypasses type safety.',
    remediation: 'Avoid unsafe package unless absolutely necessary.',
  },
  {
    id: 'MISC030', name: 'Rust Unsafe Block', severity: Severity.MEDIUM, confidence: 'medium',
    cwe: 'CWE-242', owasp: 'A04',
    pattern: /unsafe\s*\{/,
    languages: ['rust'], description: 'Rust unsafe block — memory safety guarantees suspended.',
    remediation: 'Minimize unsafe usage. Document safety invariants.',
  },
  {
    id: 'MISC031', name: 'Swift Force Unwrap', severity: Severity.LOW, confidence: 'medium',
    cwe: 'CWE-476', owasp: 'A04',
    pattern: /\w+!/,
    antiPattern: /(?:IBOutlet|IBAction|@objc|override|func\s|import|!=|!==)/,
    languages: ['swift'], description: 'Force unwrapping may cause runtime crash.',
    remediation: 'Use optional binding (if let, guard let) instead of force unwrapping.',
  },
  {
    id: 'MISC032', name: 'Hardcoded Database Credentials', severity: Severity.CRITICAL, confidence: 'high',
    cwe: 'CWE-798', owasp: 'A07',
    pattern: /(?:(?:db|database|mysql|postgres|mongo|redis)[-_.]?(?:password|passwd|pass|pwd))\s*[:=]\s*['"][^'"]{4,}['"]/i,
    antiPattern: /(?:process\.env|os\.environ|config\.|env\[|example|sample|test|your_)/i,
    languages: ALL_LANGS, description: 'Database password hardcoded in source code.',
    remediation: 'Use environment variables or a secrets manager.',
  },
  {
    id: 'MISC033', name: 'Email in Code', severity: Severity.INFO, confidence: 'medium',
    cwe: 'CWE-200', owasp: 'A05',
    pattern: /['"][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}['"]/,
    antiPattern: /(?:example|test|placeholder|noreply|no-reply|@example\.com|@test\.com|schema|pattern|regex)/i,
    languages: ALL_LANGS, description: 'Email address found in source code.',
    remediation: 'Use configuration for email addresses, avoid hardcoding.',
  },
  {
    id: 'MISC034', name: 'TODO Security Comment', severity: Severity.INFO, confidence: 'high',
    cwe: 'CWE-546', owasp: 'A04',
    pattern: /(?:\/\/|#|\/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG)\s*:?\s*.*(?:security|vuln|auth|password|credential|encrypt|token|secret|injection|xss|csrf|sanitize)/i,
    languages: ALL_LANGS, description: 'Security-related TODO comment indicates incomplete security work.',
    remediation: 'Address the security concern documented in the TODO comment.',
  },
  {
    id: 'MISC035', name: 'Terraform Sensitive Variable Exposed', severity: Severity.HIGH, confidence: 'medium',
    cwe: 'CWE-200', owasp: 'A05',
    pattern: /(?:output\s+['"][^'"]+['"]\s*\{[^}]*value\s*=\s*(?:var|local)\.(?:password|secret|key|token|credential))/i,
    languages: ALL_LANGS, description: 'Terraform output may expose sensitive variable.',
    remediation: 'Mark outputs as sensitive = true.',
  },
];

// ============================================================
// Combine all rules
// ============================================================
export const ALL_RULES: Rule[] = [
  ...brokenAccessControl,
  ...cryptoFailures,
  ...injection,
  ...insecureDesign,
  ...misconfig,
  ...vulnerableComponents,
  ...authFailures,
  ...dataIntegrity,
  ...loggingFailures,
  ...ssrf,
  ...secrets,
  ...prototypePollution,
  ...pathTraversal,
  ...additional,
];

export function getRulesForLanguage(language: string): Rule[] {
  return ALL_RULES.filter(r => r.languages.includes(language));
}

export function getRuleById(id: string): Rule | undefined {
  return ALL_RULES.find(r => r.id === id);
}

export function getRulesByOwasp(category: string): Rule[] {
  return ALL_RULES.filter(r => r.owasp === category);
}

export function getRulesBySeverity(severity: Severity): Rule[] {
  return ALL_RULES.filter(r => r.severity === severity);
}

export function getEnabledRules(disabled: string[] = []): Rule[] {
  const disabledSet = new Set(disabled);
  return ALL_RULES.filter(r => !disabledSet.has(r.id));
}
