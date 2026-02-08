import { AIFinding } from '../core/severity';
import { AIProvider, parseAIResponse } from './provider';
import { buildAnalysisPrompt } from './prompts';

const DEFAULT_MODEL = 'Qwen/Qwen2.5-Coder-32B-Instruct';
const FALLBACK_MODEL = 'bigcode/starcoder2-15b';
const HF_API_URL = 'https://api-inference.huggingface.co/models';

export class HuggingFaceProvider implements AIProvider {
  name = 'huggingface';
  private token: string | undefined;
  private model: string;

  constructor(model?: string) {
    this.token = process.env.HF_TOKEN || process.env.HUGGINGFACE_TOKEN;
    this.model = model || DEFAULT_MODEL;
  }

  isAvailable(): boolean {
    return true; // HuggingFace free tier doesn't require a token for some models
  }

  async analyze(code: string, context: string): Promise<AIFinding[]> {
    const prompt = buildAnalysisPrompt(code, context, 'security');

    try {
      const response = await this.callAPI(this.model, prompt);
      return parseAIResponse(response);
    } catch {
      try {
        // Fallback to secondary model
        const response = await this.callAPI(FALLBACK_MODEL, prompt);
        return parseAIResponse(response);
      } catch {
        return [];
      }
    }
  }

  private async callAPI(model: string, prompt: string): Promise<string> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const body = JSON.stringify({
      inputs: prompt,
      parameters: {
        max_new_tokens: 2048,
        temperature: 0.1,
        return_full_text: false,
      },
    });

    const response = await fetchWithRetry(`${HF_API_URL}/${model}`, {
      method: 'POST',
      headers,
      body,
    });

    if (!response.ok) {
      throw new Error(`HuggingFace API error: ${response.status}`);
    }

    const data = await response.json();

    if (Array.isArray(data) && data[0]?.generated_text) {
      return data[0].generated_text;
    }

    return JSON.stringify(data);
  }
}

async function fetchWithRetry(
  url: string,
  options: RequestInit,
  retries: number = 3,
  delay: number = 1000,
): Promise<Response> {
  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, options);

      // If model is loading, wait and retry
      if (response.status === 503) {
        const body = await response.json().catch(() => ({}));
        const estimatedTime = (body as any)?.estimated_time || 20;
        const waitTime = Math.min(estimatedTime * 1000, 30000);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        continue;
      }

      // Rate limited
      if (response.status === 429) {
        await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
        continue;
      }

      return response;
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
    }
  }

  throw new Error('Max retries exceeded');
}
