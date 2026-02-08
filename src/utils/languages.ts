import * as path from 'path';

export const LANGUAGE_MAP: Record<string, string> = {
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.mts': 'typescript',
  '.cts': 'typescript',
  '.py': 'python',
  '.pyw': 'python',
  '.java': 'java',
  '.go': 'go',
  '.rs': 'rust',
  '.c': 'c',
  '.h': 'c',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.hpp': 'cpp',
  '.hxx': 'cpp',
  '.cs': 'csharp',
  '.php': 'php',
  '.rb': 'ruby',
  '.swift': 'swift',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.sql': 'sql',
  '.html': 'html',
  '.htm': 'html',
  '.vue': 'javascript',
  '.svelte': 'javascript',
};

export const SUPPORTED_LANGUAGES = [
  'typescript', 'javascript', 'python', 'java', 'go', 'rust',
  'c', 'cpp', 'csharp', 'php', 'ruby', 'swift', 'kotlin',
  'shell', 'sql',
];

export function detectLanguage(filePath: string): string | null {
  const ext = path.extname(filePath).toLowerCase();
  return LANGUAGE_MAP[ext] || null;
}

export function isSupportedFile(filePath: string): boolean {
  return detectLanguage(filePath) !== null;
}

export const DEFAULT_EXCLUDE = [
  'node_modules/**',
  'dist/**',
  'build/**',
  'out/**',
  '.git/**',
  '.next/**',
  '.nuxt/**',
  'vendor/**',
  '__pycache__/**',
  '*.min.js',
  '*.min.css',
  '*.map',
  '*.lock',
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  '.env',
  '.env.*',
  'coverage/**',
  '.nyc_output/**',
  '*.d.ts',
  '*.bundle.js',
  '*.chunk.js',
];

export const CONFIG_FILES = [
  'package.json',
  'requirements.txt',
  'Pipfile',
  'pom.xml',
  'go.mod',
  'Gemfile',
  'Cargo.toml',
  'composer.json',
];

export function isConfigFile(filePath: string): boolean {
  const basename = path.basename(filePath);
  return CONFIG_FILES.includes(basename);
}
