export enum Severity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  [Severity.CRITICAL]: 5,
  [Severity.HIGH]: 4,
  [Severity.MEDIUM]: 3,
  [Severity.LOW]: 2,
  [Severity.INFO]: 1,
};

export const SEVERITY_COLORS: Record<Severity, string> = {
  [Severity.CRITICAL]: '\x1b[41m\x1b[37m',
  [Severity.HIGH]: '\x1b[31m',
  [Severity.MEDIUM]: '\x1b[33m',
  [Severity.LOW]: '\x1b[36m',
  [Severity.INFO]: '\x1b[90m',
};

export const SEVERITY_ICONS: Record<Severity, string> = {
  [Severity.CRITICAL]: '[!!!]',
  [Severity.HIGH]: '[!!]',
  [Severity.MEDIUM]: '[!]',
  [Severity.LOW]: '[~]',
  [Severity.INFO]: '[i]',
};

export function severityFromString(s: string): Severity {
  const lower = s.toLowerCase();
  if (lower in Severity) return lower as Severity;
  const map: Record<string, Severity> = {
    crit: Severity.CRITICAL,
    error: Severity.HIGH,
    warn: Severity.MEDIUM,
    warning: Severity.MEDIUM,
    note: Severity.LOW,
    information: Severity.INFO,
  };
  return map[lower] ?? Severity.MEDIUM;
}

export function meetsMinSeverity(severity: Severity, minSeverity: Severity): boolean {
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[minSeverity];
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  filePath: string;
  line: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  codeSnippet: string;
  cwe?: string;
  owasp?: string;
  remediation?: string;
  aiEnhanced?: boolean;
  fingerprint: string;
}

export interface AIFinding {
  title: string;
  description: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  line?: number;
  cwe?: string;
  remediation?: string;
}

export interface ScanResult {
  target: string;
  startTime: Date;
  endTime: Date;
  durationMs: number;
  filesScanned: number;
  filesSkipped: number;
  findings: Finding[];
  summary: ScanSummary;
  aiEnabled: boolean;
}

export interface ScanSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  topFiles: Array<{ file: string; count: number }>;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  cwe?: string;
  owasp?: string;
  pattern: RegExp;
  antiPattern?: RegExp;
  languages: string[];
  description: string;
  remediation: string;
}

export interface ScanOptions {
  target?: string;
  output?: 'terminal' | 'json' | 'sarif' | 'html';
  severity?: Severity;
  ai?: boolean;
  provider?: 'huggingface' | 'anthropic' | 'openai';
  fix?: boolean;
  quiet?: boolean;
  exclude?: string[];
  maxFileSize?: number;
  configPath?: string;
}

export interface GhostPatchConfig {
  exclude: string[];
  severity: Severity;
  ai: {
    provider: string;
    model: string;
  };
  rules: {
    disabled: string[];
    custom: Rule[];
  };
  maxFileSize: number;
  languages: string | string[];
}
