import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';
import micromatch from 'micromatch';
import { Finding, ScanResult, ScanSummary, ScanOptions, Severity, meetsMinSeverity } from './severity';
import { detectLanguage, isSupportedFile, DEFAULT_EXCLUDE, isConfigFile } from '../utils/languages';
import { loadConfig } from '../utils/config';
import { deduplicateFindings } from '../utils/fingerprint';

import * as injectionDetector from '../detectors/injection';
import * as authDetector from '../detectors/auth';
import * as cryptoDetector from '../detectors/crypto';
import * as secretsDetector from '../detectors/secrets';
import * as ssrfDetector from '../detectors/ssrf';
import * as pathTraversalDetector from '../detectors/pathtraversal';
import * as prototypeDetector from '../detectors/prototype';
import * as deserializeDetector from '../detectors/deserialize';
import * as dependencyDetector from '../detectors/dependency';
import * as misconfigDetector from '../detectors/misconfig';
import * as zerodayDetector from '../detectors/zeroday';

const ALL_DETECTORS = [
  injectionDetector,
  authDetector,
  cryptoDetector,
  secretsDetector,
  ssrfDetector,
  pathTraversalDetector,
  prototypeDetector,
  deserializeDetector,
  dependencyDetector,
  misconfigDetector,
];

export async function scan(target: string, options: ScanOptions = {}): Promise<ScanResult> {
  const startTime = new Date();
  const resolvedTarget = path.resolve(target || '.');
  const config = loadConfig(options.configPath, resolvedTarget);
  const minSeverity = options.severity || config.severity || Severity.LOW;
  const excludePatterns = options.exclude || config.exclude || DEFAULT_EXCLUDE;
  const maxFileSize = options.maxFileSize || config.maxFileSize || 1048576;

  let files: string[] = [];
  const stat = fs.statSync(resolvedTarget);

  if (stat.isFile()) {
    files = [resolvedTarget];
  } else if (stat.isDirectory()) {
    const allFiles = await glob('**/*', {
      cwd: resolvedTarget,
      nodir: true,
      absolute: true,
      ignore: excludePatterns,
    });
    files = allFiles.filter(f => {
      const relative = path.relative(resolvedTarget, f);
      return !micromatch.isMatch(relative, excludePatterns);
    });
  }

  // Filter by supported languages and file size
  let filesScanned = 0;
  let filesSkipped = 0;
  let allFindings: Finding[] = [];

  const scanPromises = files.map(async (filePath) => {
    try {
      const fileStat = fs.statSync(filePath);
      if (fileStat.size > maxFileSize) {
        filesSkipped++;
        return [];
      }

      const language = detectLanguage(filePath);
      const isConfig = isConfigFile(filePath);

      if (!language && !isConfig) {
        filesSkipped++;
        return [];
      }

      filesScanned++;
      const content = fs.readFileSync(filePath, 'utf-8');
      return scanFile(filePath, content, language || 'generic');
    } catch {
      filesSkipped++;
      return [];
    }
  });

  const results = await Promise.all(scanPromises);
  allFindings = results.flat();

  // Run zero-day suspicious pattern detection
  if (options.ai !== false) {
    for (const filePath of files) {
      try {
        const language = detectLanguage(filePath);
        if (!language) continue;
        const content = fs.readFileSync(filePath, 'utf-8');
        const suspiciousFindings = zerodayDetector.detectSuspiciousPatterns(content, filePath, language);
        allFindings.push(...suspiciousFindings);
      } catch {
        // Skip files that can't be read
      }
    }
  }

  // Deduplicate
  allFindings = deduplicateFindings(allFindings);

  // Filter by severity
  allFindings = allFindings.filter(f => meetsMinSeverity(f.severity, minSeverity));

  // Sort by severity (critical first)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  allFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const endTime = new Date();

  return {
    target: resolvedTarget,
    startTime,
    endTime,
    durationMs: endTime.getTime() - startTime.getTime(),
    filesScanned,
    filesSkipped,
    findings: allFindings,
    summary: buildSummary(allFindings),
    aiEnabled: options.ai || false,
  };
}

export function scanFile(filePath: string, content: string, language: string): Finding[] {
  const findings: Finding[] = [];

  for (const detector of ALL_DETECTORS) {
    try {
      const detectorFindings = detector.detect(content, filePath, language);
      findings.push(...detectorFindings);
    } catch {
      // Skip detector errors
    }
  }

  return findings;
}

export async function scanWithAI(
  findings: Finding[],
  files: Map<string, string>,
  provider: zerodayDetector.AIProvider,
): Promise<Finding[]> {
  const aiFindings: Finding[] = [];

  for (const [filePath, content] of files) {
    const language = detectLanguage(filePath);
    if (!language) continue;

    try {
      const results = await zerodayDetector.analyzeWithAI(content, filePath, language, provider);
      aiFindings.push(...results);
    } catch {
      // AI analysis failed for this file
    }
  }

  return [...findings, ...aiFindings];
}

function buildSummary(findings: Finding[]): ScanSummary {
  const bySeverity: Record<Severity, number> = {
    [Severity.CRITICAL]: 0,
    [Severity.HIGH]: 0,
    [Severity.MEDIUM]: 0,
    [Severity.LOW]: 0,
    [Severity.INFO]: 0,
  };

  const byCategory: Record<string, number> = {};
  const fileCount: Record<string, number> = {};

  for (const f of findings) {
    bySeverity[f.severity]++;
    const cat = f.owasp || 'other';
    byCategory[cat] = (byCategory[cat] || 0) + 1;
    fileCount[f.filePath] = (fileCount[f.filePath] || 0) + 1;
  }

  const topFiles = Object.entries(fileCount)
    .map(([file, count]) => ({ file, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    total: findings.length,
    bySeverity,
    byCategory,
    topFiles,
  };
}
