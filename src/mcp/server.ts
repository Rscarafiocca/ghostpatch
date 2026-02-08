import * as fs from 'fs';
import * as path from 'path';
import { scan, scanFile } from '../core/scanner';
import { generateReport } from '../core/reporter';
import { Finding, Severity, ScanResult } from '../core/severity';
import { detectLanguage } from '../utils/languages';
import { getAvailableProvider } from '../ai/provider';
import { detectSecretsOnly } from '../detectors/secrets';
import { runNpmAudit } from '../detectors/dependency';

// MCP protocol types
interface MCPRequest {
  jsonrpc: '2.0';
  id: number | string;
  method: string;
  params?: any;
}

interface MCPResponse {
  jsonrpc: '2.0';
  id: number | string;
  result?: any;
  error?: { code: number; message: string };
}

// Cache for scan results
let lastScanResult: ScanResult | null = null;

const TOOLS = [
  {
    name: 'ghostpatch_scan',
    description: 'Run a full security scan on a project directory. Returns findings with severity, CWE codes, and remediation advice.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Directory or file path to scan (default: current directory)' },
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'], description: 'Minimum severity level to report' },
        output: { type: 'string', enum: ['json', 'terminal', 'sarif'], description: 'Output format' },
      },
    },
  },
  {
    name: 'ghostpatch_scan_file',
    description: 'Scan a single file for security vulnerabilities.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to the file to scan' },
        content: { type: 'string', description: 'File content (if not reading from disk)' },
      },
      required: ['path'],
    },
  },
  {
    name: 'ghostpatch_findings',
    description: 'Get current scan findings with optional filters.',
    inputSchema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
        file: { type: 'string', description: 'Filter by file path (substring match)' },
        ruleId: { type: 'string', description: 'Filter by rule ID' },
        limit: { type: 'number', description: 'Maximum results to return', default: 50 },
      },
    },
  },
  {
    name: 'ghostpatch_finding',
    description: 'Get detailed information about a specific finding by its ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Finding ID' },
      },
      required: ['id'],
    },
  },
  {
    name: 'ghostpatch_secrets',
    description: 'Scan for hardcoded secrets, API keys, tokens, and credentials.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to scan' },
      },
    },
  },
  {
    name: 'ghostpatch_dependencies',
    description: 'Check project dependencies for known vulnerabilities (npm audit, pip, etc.).',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Project directory path' },
      },
    },
  },
  {
    name: 'ghostpatch_ai_analyze',
    description: 'Run AI-powered deep security analysis on code. Uses HuggingFace (free), Anthropic, or OpenAI.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Code to analyze' },
        file: { type: 'string', description: 'File path for context' },
        provider: { type: 'string', enum: ['huggingface', 'anthropic', 'openai'], description: 'AI provider' },
      },
      required: ['code'],
    },
  },
  {
    name: 'ghostpatch_status',
    description: 'Get scanner status, configuration, and stats from last scan.',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
];

async function handleToolCall(name: string, args: any): Promise<any> {
  switch (name) {
    case 'ghostpatch_scan': {
      const target = args.path || process.cwd();
      const result = await scan(target, {
        severity: args.severity as Severity,
      });
      lastScanResult = result;

      if (args.output === 'json' || args.output === 'sarif') {
        return generateReport(result, args.output);
      }

      return {
        target: result.target,
        filesScanned: result.filesScanned,
        duration: `${result.durationMs}ms`,
        summary: result.summary,
        findings: result.findings.slice(0, 100).map(formatFindingForMCP),
      };
    }

    case 'ghostpatch_scan_file': {
      const filePath = path.resolve(args.path);
      const content = args.content || fs.readFileSync(filePath, 'utf-8');
      const language = detectLanguage(filePath) || 'generic';
      const findings = scanFile(filePath, content, language);

      return {
        file: filePath,
        language,
        findings: findings.map(formatFindingForMCP),
        total: findings.length,
      };
    }

    case 'ghostpatch_findings': {
      if (!lastScanResult) {
        return { error: 'No scan results available. Run ghostpatch_scan first.' };
      }

      let findings = lastScanResult.findings;

      if (args.severity) {
        const severityOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        const minLevel = severityOrder[args.severity] || 0;
        findings = findings.filter(f => (severityOrder[f.severity] || 0) >= minLevel);
      }

      if (args.file) {
        findings = findings.filter(f => f.filePath.includes(args.file));
      }

      if (args.ruleId) {
        findings = findings.filter(f => f.ruleId === args.ruleId);
      }

      const limit = args.limit || 50;
      return {
        total: findings.length,
        showing: Math.min(findings.length, limit),
        findings: findings.slice(0, limit).map(formatFindingForMCP),
      };
    }

    case 'ghostpatch_finding': {
      if (!lastScanResult) {
        return { error: 'No scan results available. Run ghostpatch_scan first.' };
      }

      const finding = lastScanResult.findings.find(f => f.id === args.id);
      if (!finding) {
        return { error: `Finding not found: ${args.id}` };
      }

      return finding;
    }

    case 'ghostpatch_secrets': {
      const target = args.path || process.cwd();
      const result = await scan(target, { severity: Severity.LOW });
      const secretsFindings = result.findings.filter(f =>
        f.ruleId.startsWith('SEC-') ||
        f.title.toLowerCase().includes('secret') ||
        f.title.toLowerCase().includes('key') ||
        f.title.toLowerCase().includes('token') ||
        f.title.toLowerCase().includes('password')
      );

      return {
        total: secretsFindings.length,
        findings: secretsFindings.map(formatFindingForMCP),
      };
    }

    case 'ghostpatch_dependencies': {
      const target = args.path || process.cwd();
      const result = await scan(target, { severity: Severity.LOW });
      const depFindings = result.findings.filter(f =>
        f.ruleId.startsWith('DEP-') || f.owasp === 'A06'
      );

      // Also try npm audit
      const npmFindings = runNpmAudit(target);

      return {
        total: depFindings.length + npmFindings.length,
        staticAnalysis: depFindings.map(formatFindingForMCP),
        npmAudit: npmFindings.map(formatFindingForMCP),
      };
    }

    case 'ghostpatch_ai_analyze': {
      const provider = getAvailableProvider(args.provider);
      if (!provider) {
        return { error: 'No AI provider available. Set HF_TOKEN, ANTHROPIC_API_KEY, or OPENAI_API_KEY.' };
      }

      const findings = await provider.analyze(
        args.code,
        args.file ? `File: ${args.file}` : 'Code snippet'
      );

      return {
        provider: provider.name,
        findings,
        total: findings.length,
      };
    }

    case 'ghostpatch_status': {
      return {
        version: '1.0.0',
        lastScan: lastScanResult ? {
          target: lastScanResult.target,
          time: lastScanResult.startTime.toISOString(),
          filesScanned: lastScanResult.filesScanned,
          findingsTotal: lastScanResult.summary.total,
          summary: lastScanResult.summary.bySeverity,
        } : null,
        aiProviders: {
          huggingface: 'available (free)',
          anthropic: process.env.ANTHROPIC_API_KEY ? 'configured' : 'not configured',
          openai: process.env.OPENAI_API_KEY ? 'configured' : 'not configured',
        },
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

function formatFindingForMCP(f: Finding) {
  return {
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    file: f.filePath,
    line: f.line,
    description: f.description,
    cwe: f.cwe,
    owasp: f.owasp,
    remediation: f.remediation,
    aiEnhanced: f.aiEnhanced || false,
  };
}

// ============================================================
// MCP Server (stdio transport)
// ============================================================
export async function startMCPServer(): Promise<void> {
  const readline = await import('readline');

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  function send(response: MCPResponse): void {
    const json = JSON.stringify(response);
    process.stdout.write(json + '\n');
  }

  rl.on('line', async (line: string) => {
    let request: MCPRequest;
    try {
      request = JSON.parse(line);
    } catch {
      return;
    }

    try {
      switch (request.method) {
        case 'initialize':
          send({
            jsonrpc: '2.0',
            id: request.id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: {
                name: 'ghostpatch',
                version: '1.0.0',
              },
            },
          });
          break;

        case 'notifications/initialized':
          // No response needed for notifications
          break;

        case 'tools/list':
          send({
            jsonrpc: '2.0',
            id: request.id,
            result: { tools: TOOLS },
          });
          break;

        case 'tools/call': {
          const { name, arguments: args } = request.params;
          const result = await handleToolCall(name, args || {});
          send({
            jsonrpc: '2.0',
            id: request.id,
            result: {
              content: [{
                type: 'text',
                text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
              }],
            },
          });
          break;
        }

        default:
          send({
            jsonrpc: '2.0',
            id: request.id,
            error: { code: -32601, message: `Method not found: ${request.method}` },
          });
      }
    } catch (err: any) {
      send({
        jsonrpc: '2.0',
        id: request.id,
        error: { code: -32603, message: err.message },
      });
    }
  });

  // Keep the server running
  process.stderr.write('GhostPatch MCP server started (stdio)\n');
}
