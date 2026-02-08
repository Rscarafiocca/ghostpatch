import { AIFinding, Severity, severityFromString } from '../core/severity';

export interface AIProvider {
  name: string;
  analyze(code: string, context: string): Promise<AIFinding[]>;
  isAvailable(): boolean;
}

export function getAvailableProvider(preferred?: string): AIProvider | null {
  // Import providers lazily
  const { HuggingFaceProvider } = require('./huggingface');
  const { AnthropicProvider } = require('./anthropic');
  const { OpenAIProvider } = require('./openai');

  if (preferred) {
    switch (preferred) {
      case 'anthropic': {
        const p = new AnthropicProvider();
        if (p.isAvailable()) return p;
        break;
      }
      case 'openai': {
        const p = new OpenAIProvider();
        if (p.isAvailable()) return p;
        break;
      }
      case 'huggingface': {
        const p = new HuggingFaceProvider();
        return p;
      }
    }
  }

  // Auto-detect: prefer Anthropic > OpenAI > HuggingFace
  const anthropic = new AnthropicProvider();
  if (anthropic.isAvailable()) return anthropic;

  const openai = new OpenAIProvider();
  if (openai.isAvailable()) return openai;

  // HuggingFace is always available (free tier)
  return new HuggingFaceProvider();
}

export function parseAIResponse(response: string): AIFinding[] {
  try {
    // Try to extract JSON from the response
    const jsonMatch = response.match(/\{[\s\S]*"findings"[\s\S]*\}/);
    if (!jsonMatch) return [];

    const parsed = JSON.parse(jsonMatch[0]);
    if (!Array.isArray(parsed.findings)) return [];

    return parsed.findings
      .filter((f: any) => f.title && f.description)
      .map((f: any) => ({
        title: String(f.title),
        description: String(f.description),
        severity: severityFromString(f.severity || 'medium'),
        confidence: (['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'medium') as 'high' | 'medium' | 'low',
        line: typeof f.line === 'number' ? f.line : undefined,
        cwe: f.cwe ? String(f.cwe) : undefined,
        remediation: f.remediation ? String(f.remediation) : undefined,
      }));
  } catch {
    return [];
  }
}
