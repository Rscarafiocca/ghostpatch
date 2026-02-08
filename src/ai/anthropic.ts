import { AIFinding } from '../core/severity';
import { AIProvider, parseAIResponse } from './provider';
import { buildAnalysisPrompt } from './prompts';

export class AnthropicProvider implements AIProvider {
  name = 'anthropic';
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = process.env.ANTHROPIC_API_KEY;
  }

  isAvailable(): boolean {
    return !!this.apiKey;
  }

  async analyze(code: string, context: string): Promise<AIFinding[]> {
    if (!this.apiKey) return [];

    const prompt = buildAnalysisPrompt(code, context, 'security');

    try {
      // Try to use the SDK if available
      const Anthropic = require('@anthropic-ai/sdk');
      const client = new Anthropic({ apiKey: this.apiKey });

      const response = await client.messages.create({
        model: 'claude-sonnet-4-5-20250929',
        max_tokens: 4096,
        messages: [{
          role: 'user',
          content: prompt,
        }],
      });

      const text = response.content
        .filter((c: any) => c.type === 'text')
        .map((c: any) => c.text)
        .join('');

      return parseAIResponse(text);
    } catch (sdkError) {
      // Fallback to direct API call
      try {
        return await this.callDirectAPI(prompt);
      } catch {
        return [];
      }
    }
  }

  private async callDirectAPI(prompt: string): Promise<AIFinding[]> {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.apiKey!,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-5-20250929',
        max_tokens: 4096,
        messages: [{
          role: 'user',
          content: prompt,
        }],
      }),
    });

    if (!response.ok) {
      throw new Error(`Anthropic API error: ${response.status}`);
    }

    const data: any = await response.json();
    const text = data.content
      ?.filter((c: any) => c.type === 'text')
      ?.map((c: any) => c.text)
      ?.join('') || '';

    return parseAIResponse(text);
  }
}
