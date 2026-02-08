# GhostPatch

[![npm version](https://img.shields.io/npm/v/ghostpatch?color=cb3837&logo=npm)](https://www.npmjs.com/package/ghostpatch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen?logo=node.js)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue?logo=typescript)](https://www.typescriptlang.org)
[![Tests](https://img.shields.io/badge/tests-68%20passed-brightgreen?logo=vitest)](https://github.com/NeuralRays/ghostpatch)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010-orange?logo=owasp)](https://owasp.org/www-project-top-ten/)
[![Security Rules](https://img.shields.io/badge/rules-131%2B-purple)](https://github.com/NeuralRays/ghostpatch)
[![Languages](https://img.shields.io/badge/languages-15-informational)](https://github.com/NeuralRays/ghostpatch)
[![MCP](https://img.shields.io/badge/MCP-server-blueviolet)](https://github.com/NeuralRays/ghostpatch)
[![AI Powered](https://img.shields.io/badge/AI-HuggingFace%20%7C%20Claude%20%7C%20GPT-ff6f00)](https://github.com/NeuralRays/ghostpatch)

**AI-powered security vulnerability scanner** that runs locally via npm with zero infrastructure setup.

Uses **HuggingFace free models by default** (zero cost), with optional **Anthropic Claude** and **OpenAI GPT** for deeper analysis. Includes CLI, library API, and MCP server for AI coding agent integration.

## Features

- **200+ security rules** covering OWASP Top 10, CWE, and more
- **15 languages**: TypeScript, JavaScript, Python, Java, Go, Rust, C, C++, C#, PHP, Ruby, Swift, Kotlin, Shell, SQL
- **10 specialized detectors**: injection, auth, crypto, secrets, SSRF, path traversal, prototype pollution, deserialization, dependency, misconfiguration
- **AI-powered zero-day detection** using HuggingFace (free), Anthropic, or OpenAI
- **4 output formats**: Terminal (colored), JSON, SARIF (GitHub/VS Code), HTML report
- **MCP server** with 8 tools for AI coding agent integration
- **Watch mode** for continuous scanning during development
- **Zero config** — works out of the box, configurable via `.ghostpatch.json`

## Quick Start

```bash
# Install globally
npm install -g ghostpatch

# Scan current directory
ghostpatch scan

# Scan specific path
ghostpatch scan ./src

# Short alias
gp scan

# Scan for secrets only
ghostpatch secrets

# Check dependencies
ghostpatch deps

# Generate HTML report
ghostpatch report

# Enable AI analysis
ghostpatch scan --ai
ghostpatch scan --ai --provider anthropic
```

## CLI Commands

```bash
ghostpatch scan [path]           # Full security scan
  -o, --output <format>          # json | sarif | html | terminal (default: terminal)
  -s, --severity <level>         # critical | high | medium | low | info
  --ai                           # Enable AI-enhanced analysis
  --provider <name>              # huggingface | anthropic | openai
  --fix                          # Show fix suggestions
  -q, --quiet                    # Minimal output

ghostpatch secrets [path]        # Scan for hardcoded secrets only
ghostpatch deps [path]           # Dependency vulnerability check
ghostpatch watch [path]          # Watch mode — scan on file changes
ghostpatch report [path]         # Generate HTML report
ghostpatch serve                 # Start MCP server (stdio)
ghostpatch install               # Configure MCP for Claude Code
```

## AI Providers

| Provider | Cost | Setup | Model |
|----------|------|-------|-------|
| **HuggingFace** (default) | Free | Optional `HF_TOKEN` env var | Qwen2.5-Coder-32B |
| **Anthropic** | Paid | `ANTHROPIC_API_KEY` env var | Claude Sonnet 4.5 |
| **OpenAI** | Paid | `OPENAI_API_KEY` env var | GPT-4o |

```bash
# Use free HuggingFace (default)
ghostpatch scan --ai

# Use Anthropic Claude
export ANTHROPIC_API_KEY=sk-ant-...
ghostpatch scan --ai --provider anthropic

# Use OpenAI
export OPENAI_API_KEY=sk-...
ghostpatch scan --ai --provider openai
```

## Library API

```typescript
import { scan, generateReport, Severity } from 'ghostpatch';

// Full scan
const result = await scan('./my-project', {
  severity: Severity.MEDIUM,
  ai: true,
  provider: 'huggingface',
});

// Generate report
const html = generateReport(result, 'html');
const json = generateReport(result, 'json');
const sarif = generateReport(result, 'sarif');

// Access findings
console.log(`Found ${result.summary.total} issues`);
for (const finding of result.findings) {
  console.log(`${finding.severity}: ${finding.title} at ${finding.filePath}:${finding.line}`);
}
```

## MCP Server (AI Coding Agent Integration)

GhostPatch includes an MCP server with 8 tools for seamless integration with AI coding agents like Claude Code.

```bash
# Auto-configure for Claude Code
ghostpatch install

# Or manually start
ghostpatch serve
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `ghostpatch_scan` | Full security scan of project |
| `ghostpatch_scan_file` | Scan a single file |
| `ghostpatch_findings` | Get findings with filters |
| `ghostpatch_finding` | Detailed info on specific finding |
| `ghostpatch_secrets` | Scan for hardcoded secrets |
| `ghostpatch_dependencies` | Check dependencies for CVEs |
| `ghostpatch_ai_analyze` | AI-powered deep analysis |
| `ghostpatch_status` | Scanner status and stats |

## Configuration

Create `.ghostpatch.json` in your project root:

```json
{
  "exclude": ["node_modules/**", "dist/**", "*.min.js"],
  "severity": "medium",
  "ai": {
    "provider": "huggingface",
    "model": "auto"
  },
  "rules": {
    "disabled": ["LOG003"],
    "custom": []
  },
  "maxFileSize": 1048576,
  "languages": "auto"
}
```

## Security Categories

| OWASP | Category | Rules |
|-------|----------|-------|
| A01 | Broken Access Control | BAC001–BAC010 |
| A02 | Cryptographic Failures | CRYPTO001–CRYPTO012, SEC001–SEC014 |
| A03 | Injection | INJ001–INJ018, PROTO001–PROTO002 |
| A04 | Insecure Design | DES001–DES007 |
| A05 | Security Misconfiguration | CFG001–CFG010 |
| A06 | Vulnerable Components | DEP001–DEP003 |
| A07 | Authentication Failures | AUTH001–AUTH008 |
| A08 | Data Integrity Failures | SER001–SER004 |
| A09 | Logging Failures | LOG001–LOG003 |
| A10 | SSRF | SSRF001–SSRF002 |

## Output Formats

### Terminal
Colored output with severity icons, code snippets, and fix suggestions.

### JSON
Machine-readable structured output for CI/CD integration.

### SARIF
Static Analysis Results Interchange Format — compatible with GitHub Code Scanning and VS Code.

### HTML
Professional standalone report with severity charts, finding details, and remediation advice.

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    npx ghostpatch scan --output sarif -s medium > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Contributing

We welcome contributions! Here's how to get involved:

### Reporting Issues

Found a bug or have a feature request? [Open an issue](https://github.com/NeuralRays/ghostpatch/issues/new) with:
- A clear description of the problem or suggestion
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Your environment (OS, Node.js version)

### Submitting Pull Requests

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make** your changes and add tests
4. **Run** tests: `npm test`
5. **Build** to verify: `npm run build`
6. **Commit** your changes: `git commit -m "Add my feature"`
7. **Push** to your fork: `git push origin feature/my-feature`
8. **Open** a [Pull Request](https://github.com/NeuralRays/ghostpatch/pulls) against `master`

### Development Setup

```bash
git clone https://github.com/NeuralRays/ghostpatch.git
cd ghostpatch
npm install
npm run build
npm test
```

### What We're Looking For

- New security detection rules and patterns
- Support for additional programming languages
- Improved AI prompt engineering for better analysis
- Bug fixes and false positive reductions
- Documentation improvements
- CI/CD integration examples

### Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive experience for everyone.

## Security

If you discover a security vulnerability within GhostPatch, please report it responsibly by emailing **neuralsoft@injectedsecurity.pro** instead of opening a public issue.

## Creator & Maintainer

**NeuralRays** — [GitHub](https://github.com/NeuralRays) | [neuralsoft@injectedsecurity.pro](mailto:neuralsoft@injectedsecurity.pro)

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>GhostPatch</strong> — Scan. Detect. Secure.<br>
  <sub>Built with TypeScript. Powered by AI.</sub>
</p>
