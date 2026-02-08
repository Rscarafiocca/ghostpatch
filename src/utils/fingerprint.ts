import * as crypto from 'crypto';

export function generateFingerprint(...parts: string[]): string {
  const hash = crypto.createHash('sha256');
  hash.update(parts.join('::'));
  return hash.digest('hex').substring(0, 16);
}

export function deduplicateFindings<T extends { fingerprint: string }>(findings: T[]): T[] {
  const seen = new Set<string>();
  const result: T[] = [];

  for (const finding of findings) {
    if (!seen.has(finding.fingerprint)) {
      seen.add(finding.fingerprint);
      result.push(finding);
    }
  }

  return result;
}
