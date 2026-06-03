// AI Sales Assistant service — the single place that talks to the Anthropic
// Messages API for the demo. Keeps the network call out of the hook/components.
// The live demo ships no API key, so the request fails and the caller surfaces
// "AI unavailable"; on success we mirror the reference's reply extraction.
import { AI_SYSTEM_PROMPT } from '../constants/clDemoData';
import type { AiMessage } from '../types/clDemoTypes';

const ENDPOINT = 'https://api.anthropic.com/v1/messages';
const MODEL = 'claude-sonnet-4-20250514';
const MAX_TOKENS = 1000;
// Only the last 10 turns are sent, matching the reference sendAI().
const HISTORY_WINDOW = 10;

export async function sendAiMessage(history: AiMessage[]): Promise<string> {
  const r = await fetch(ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: MAX_TOKENS,
      system: AI_SYSTEM_PROMPT,
      messages: history.slice(-HISTORY_WINDOW),
    }),
  });
  const d = await r.json();
  return d?.content?.[0]?.text || d?.error?.message || 'No response.';
}
