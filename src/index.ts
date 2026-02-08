// GhostPatch — AI-Powered Security Vulnerability Scanner
// Library API

export { scan, scanFile, scanWithAI } from './core/scanner';
export { generateReport, reportJSON, reportSARIF, reportHTML, reportTerminal } from './core/reporter';
export {
  Finding,
  AIFinding,
  ScanResult,
  ScanSummary,
  ScanOptions,
  Rule,
  GhostPatchConfig,
  Severity,
  SEVERITY_ORDER,
  meetsMinSeverity,
  severityFromString,
} from './core/severity';
export { ALL_RULES, getRulesForLanguage, getRuleById, getRulesByOwasp, getRulesBySeverity, getEnabledRules } from './core/rules';
export { getAvailableProvider, AIProvider } from './ai/provider';
export { loadConfig, getDefaultConfig } from './utils/config';
export { detectLanguage, isSupportedFile, SUPPORTED_LANGUAGES } from './utils/languages';
export { generateFingerprint, deduplicateFindings } from './utils/fingerprint';
export { startMCPServer } from './mcp/server';
