import * as fs from 'fs';
import * as path from 'path';
import { GhostPatchConfig, Severity } from '../core/severity';
import { DEFAULT_EXCLUDE } from './languages';

const DEFAULT_CONFIG: GhostPatchConfig = {
  exclude: DEFAULT_EXCLUDE,
  severity: Severity.LOW,
  ai: {
    provider: 'huggingface',
    model: 'auto',
  },
  rules: {
    disabled: [],
    custom: [],
  },
  maxFileSize: 1048576, // 1MB
  languages: 'auto',
};

export function loadConfig(configPath?: string, basePath?: string): GhostPatchConfig {
  const searchPaths = configPath
    ? [configPath]
    : [
        path.join(basePath || process.cwd(), '.ghostpatch.json'),
        path.join(basePath || process.cwd(), '.ghostpatchrc'),
        path.join(basePath || process.cwd(), 'ghostpatch.config.json'),
      ];

  for (const p of searchPaths) {
    try {
      if (fs.existsSync(p)) {
        const content = fs.readFileSync(p, 'utf-8');
        const userConfig = JSON.parse(content);
        return mergeConfig(DEFAULT_CONFIG, userConfig);
      }
    } catch {
      // Skip invalid config files
    }
  }

  return { ...DEFAULT_CONFIG };
}

function mergeConfig(defaults: GhostPatchConfig, user: Partial<GhostPatchConfig>): GhostPatchConfig {
  return {
    exclude: user.exclude || defaults.exclude,
    severity: user.severity || defaults.severity,
    ai: {
      ...defaults.ai,
      ...(user.ai || {}),
    },
    rules: {
      disabled: user.rules?.disabled || defaults.rules.disabled,
      custom: user.rules?.custom || defaults.rules.custom,
    },
    maxFileSize: user.maxFileSize || defaults.maxFileSize,
    languages: user.languages || defaults.languages,
  };
}

export function getDefaultConfig(): GhostPatchConfig {
  return { ...DEFAULT_CONFIG };
}
