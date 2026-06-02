// Chat state for the AI Sales Assistant tab. Mirrors the reference sendAI():
// posts the running history to the Anthropic Messages API and appends the
// reply. The live demo ships no API key, so the request fails and we surface
// "AI unavailable" — identical behavior, kept honest.
import { useCallback, useState } from 'react';
import { AI_GREETING, AI_SYSTEM_PROMPT } from '../constants/clDemoData';
import type { AiMessage } from '../types/clDemoTypes';

interface ChatBubble extends AiMessage {
  thinking?: boolean;
  unavailable?: boolean;
}

export function useAiAssistant() {
  const [messages, setMessages] = useState<ChatBubble[]>([
    { role: 'assistant', content: AI_GREETING },
  ]);
  const [history, setHistory] = useState<AiMessage[]>([]);

  const clear = useCallback(() => {
    setMessages([{ role: 'assistant', content: 'Chat cleared. How can I help?' }]);
    setHistory([]);
  }, []);

  const send = useCallback(
    async (raw: string) => {
      const msg = raw.trim();
      if (!msg) return;

      const nextHistory: AiMessage[] = [...history, { role: 'user', content: msg }];
      setHistory(nextHistory);
      setMessages((m) => [
        ...m,
        { role: 'user', content: msg },
        { role: 'assistant', content: 'Thinking…', thinking: true },
      ]);

      try {
        const r = await fetch('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 1000,
            system: AI_SYSTEM_PROMPT,
            messages: nextHistory.slice(-10),
          }),
        });
        const d = await r.json();
        const reply: string = d?.content?.[0]?.text || d?.error?.message || 'No response.';
        setHistory((h) => [...h, { role: 'assistant', content: reply }]);
        setMessages((m) => [
          ...m.filter((b) => !b.thinking),
          { role: 'assistant', content: reply },
        ]);
      } catch {
        setMessages((m) => [
          ...m.filter((b) => !b.thinking),
          { role: 'assistant', content: 'AI unavailable — check connection.', unavailable: true },
        ]);
      }
    },
    [history],
  );

  return { messages, clear, send };
}
