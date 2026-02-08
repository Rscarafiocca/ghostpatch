import { AIFinding } from '../core/severity';
import { AIProvider, parseAIResponse } from './provider';
import { buildAnalysisPrompt } from './prompts';

export class OpenAIProvider implements AIProvider {
  name = 'openai';
  private apiKey: string | undefined;

  constructor() {
    this.apiKey = process.env.OPENAI_API_KEY;
  }

  isAvailable(): boolean {
    return !!this.apiKey;
  }

  async analyze(code: string, context: string): Promise<AIFinding[]> {
    if (!this.apiKey) return [];

    const prompt = buildAnalysisPrompt(code, context, 'security');

    try {
      // Try to use the SDK if available
      const OpenAI = require('openai');
      const client = new OpenAI({ apiKey: this.apiKey });

      const response = await client.chat.completions.create({
        model: 'gpt-4o',
        messages: [{
          role: 'user',
          content: prompt,
        }],
        temperature: 0.1,
        max_tokens: 4096,
      });

      const text = response.choices[0]?.message?.content || '';
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
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.apiKey}`,
      },
      body: JSON.stringify({
        model: 'gpt-4o',
        messages: [{
          role: 'user',
          content: prompt,
        }],
        temperature: 0.1,
        max_tokens: 4096,
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.status}`);
    }

    const data: any = await response.json();
    const text = data.choices?.[0]?.message?.content || '';
    return parseAIResponse(text);
  }
}
