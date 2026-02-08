#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { scan } from '../core/scanner';
import { generateReport } from '../core/reporter';
import { Severity } from '../core/severity';
import { getAvailableProvider } from '../ai/provider';

const program = new Command();

program
  .name('ghostpatch')
  .description('AI-powered security vulnerability scanner')
  .version('1.0.0');

// ============================================================
// scan command
// ============================================================
program
  .command('scan')
  .description('Scan for security vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('-o, --output <format>', 'Output format: terminal, json, sarif, html', 'terminal')
  .option('-s, --severity <level>', 'Minimum severity: critical, high, medium, low, info', 'low')
  .option('--ai', 'Enable AI-enhanced analysis')
  .option('--provider <name>', 'AI provider: huggingface, anthropic, openai')
  .option('--fix', 'Show auto-fix suggestions')
  .option('-q, --quiet', 'Minimal output')
  .option('--exclude <patterns...>', 'Additional exclude patterns')
  .option('--max-file-size <bytes>', 'Maximum file size in bytes', '1048576')
  .option('--config <path>', 'Path to config file')
  .action(async (scanPath: string, options: any) => {
    try {
      const resolvedPath = path.resolve(scanPath);

      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path does not exist: ${resolvedPath}`);
        process.exit(1);
      }

      if (!options.quiet) {
        console.log('\n  GhostPatch v1.0.0 — AI-Powered Security Scanner\n');
        console.log(`  Scanning: ${resolvedPath}\n`);
      }

      const result = await scan(resolvedPath, {
        output: options.output,
        severity: options.severity as Severity,
        ai: options.ai,
        provider: options.provider,
        fix: options.fix,
        quiet: options.quiet,
        exclude: options.exclude,
        maxFileSize: parseInt(options.maxFileSize, 10),
        configPath: options.config,
      });

      // If AI is enabled, run AI analysis
      if (options.ai) {
        const provider = getAvailableProvider(options.provider);
        if (provider && provider.isAvailable()) {
          if (!options.quiet) {
            console.log(`  AI Provider: ${provider.name}\n`);
          }
          // AI analysis would happen here on suspicious findings
        }
      }

      const report = generateReport(result, options.output, options.quiet);

      if (options.output === 'json' || options.output === 'sarif') {
        console.log(report);
      } else if (options.output === 'html') {
        const outputFile = path.join(process.cwd(), 'ghostpatch-report.html');
        fs.writeFileSync(outputFile, report, 'utf-8');
        console.log(`  HTML report saved to: ${outputFile}\n`);
      } else {
        console.log(report);
      }

      // Exit with non-zero if critical/high findings
      const criticalOrHigh = (result.summary.bySeverity[Severity.CRITICAL] || 0)
        + (result.summary.bySeverity[Severity.HIGH] || 0);
      if (criticalOrHigh > 0) {
        process.exit(1);
      }
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// ============================================================
// secrets command
// ============================================================
program
  .command('secrets')
  .description('Scan for hardcoded secrets and API keys')
  .argument('[path]', 'Path to scan', '.')
  .option('-o, --output <format>', 'Output format', 'terminal')
  .option('-q, --quiet', 'Minimal output')
  .action(async (scanPath: string, options: any) => {
    try {
      const resolvedPath = path.resolve(scanPath);
      if (!options.quiet) {
        console.log('\n  GhostPatch — Secrets Scanner\n');
      }

      const result = await scan(resolvedPath, {
        output: options.output,
        severity: Severity.LOW,
      });

      // Filter to only secrets-related findings
      const secretsResult = {
        ...result,
        findings: result.findings.filter(f =>
          f.ruleId.startsWith('SEC-') ||
          f.ruleId.startsWith('SEC') ||
          f.title.toLowerCase().includes('secret') ||
          f.title.toLowerCase().includes('key') ||
          f.title.toLowerCase().includes('token') ||
          f.title.toLowerCase().includes('password') ||
          f.title.toLowerCase().includes('credential')
        ),
      };
      secretsResult.summary.total = secretsResult.findings.length;

      const report = generateReport(secretsResult, options.output, options.quiet);
      console.log(report);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// ============================================================
// deps command
// ============================================================
program
  .command('deps')
  .description('Check dependencies for known vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('-o, --output <format>', 'Output format', 'terminal')
  .action(async (scanPath: string, options: any) => {
    try {
      const resolvedPath = path.resolve(scanPath);
      console.log('\n  GhostPatch — Dependency Scanner\n');

      const result = await scan(resolvedPath, {
        output: options.output,
        severity: Severity.LOW,
      });

      const depsResult = {
        ...result,
        findings: result.findings.filter(f =>
          f.ruleId.startsWith('DEP-') ||
          f.owasp === 'A06'
        ),
      };
      depsResult.summary.total = depsResult.findings.length;

      const report = generateReport(depsResult, options.output);
      console.log(report);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// ============================================================
// watch command
// ============================================================
program
  .command('watch')
  .description('Watch mode — scan on file changes')
  .argument('[path]', 'Path to watch', '.')
  .option('-s, --severity <level>', 'Minimum severity', 'medium')
  .option('-q, --quiet', 'Minimal output')
  .action(async (watchPath: string, options: any) => {
    try {
      const resolvedPath = path.resolve(watchPath);
      console.log('\n  GhostPatch — Watch Mode\n');
      console.log(`  Watching: ${resolvedPath}\n`);

      const chokidar = require('chokidar');
      const watcher = chokidar.watch(resolvedPath, {
        ignored: ['**/node_modules/**', '**/dist/**', '**/.git/**'],
        persistent: true,
        ignoreInitial: true,
      });

      let scanTimeout: NodeJS.Timeout | null = null;

      const runScan = async () => {
        console.log('\n  File change detected. Scanning...\n');
        const result = await scan(resolvedPath, {
          severity: options.severity as Severity,
          quiet: true,
        });
        const report = generateReport(result, 'terminal', options.quiet);
        console.log(report);
      };

      watcher.on('change', () => {
        if (scanTimeout) clearTimeout(scanTimeout);
        scanTimeout = setTimeout(runScan, 500);
      });

      watcher.on('add', () => {
        if (scanTimeout) clearTimeout(scanTimeout);
        scanTimeout = setTimeout(runScan, 500);
      });

      // Initial scan
      await runScan();

      console.log('  Watching for changes... (Ctrl+C to stop)\n');
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// ============================================================
// report command
// ============================================================
program
  .command('report')
  .description('Generate HTML security report')
  .argument('[path]', 'Path to scan', '.')
  .option('-o, --output <file>', 'Output file', 'ghostpatch-report.html')
  .option('-s, --severity <level>', 'Minimum severity', 'low')
  .option('--ai', 'Enable AI analysis')
  .action(async (scanPath: string, options: any) => {
    try {
      const resolvedPath = path.resolve(scanPath);
      console.log('\n  GhostPatch — Generating Report\n');

      const result = await scan(resolvedPath, {
        severity: options.severity as Severity,
        ai: options.ai,
      });

      const html = generateReport(result, 'html');
      const outputFile = path.resolve(options.output);
      fs.writeFileSync(outputFile, html, 'utf-8');
      console.log(`  Report saved to: ${outputFile}`);
      console.log(`  Findings: ${result.summary.total}\n`);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// ============================================================
// serve command (MCP server)
// ============================================================
program
  .command('serve')
  .description('Start MCP server for AI coding agents')
  .action(async () => {
    const { startMCPServer } = require('../mcp/server');
    await startMCPServer();
  });

// ============================================================
// install command
// ============================================================
program
  .command('install')
  .description('Configure GhostPatch MCP for Claude Code')
  .action(async () => {
    try {
      const home = process.env.HOME || process.env.USERPROFILE || '';
      const claudeConfigDir = path.join(home, '.claude');
      const mcpConfigPath = path.join(claudeConfigDir, 'mcp_servers.json');

      if (!fs.existsSync(claudeConfigDir)) {
        fs.mkdirSync(claudeConfigDir, { recursive: true });
      }

      let config: any = {};
      if (fs.existsSync(mcpConfigPath)) {
        config = JSON.parse(fs.readFileSync(mcpConfigPath, 'utf-8'));
      }

      config.ghostpatch = {
        command: 'node',
        args: [path.resolve(__dirname, '../mcp/server.js')],
      };

      fs.writeFileSync(mcpConfigPath, JSON.stringify(config, null, 2), 'utf-8');
      console.log('\n  GhostPatch MCP server configured for Claude Code!');
      console.log(`  Config: ${mcpConfigPath}\n`);
    } catch (err: any) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
  });

// ============================================================
// Default command (scan current directory)
// ============================================================
program
  .action(async () => {
    // If no command provided, run scan on current directory
    await program.parseAsync(['node', 'ghostpatch', 'scan', '.']);
  });

program.parse();
