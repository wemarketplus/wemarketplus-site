import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import {
  appendMessage,
  resetConversation,
  setDraftPrompt,
  setSending,
} from '../store/aiAssistantSlice';
import { stubAssistantReply } from '../utils/stubResponse';

export function useAiAssistant() {
  const dispatch = useAppDispatch();
  const state = useAppSelector((s) => s.aiAssistant);

  const send = useCallback(
    async (prompt: string) => {
      const trimmed = prompt.trim();
      if (!trimmed) return;
      const now = new Date().toISOString();
      dispatch(
        appendMessage({
          id: `m-${Date.now()}`,
          role: 'user',
          content: trimmed,
          createdAt: now,
        }),
      );
      dispatch(setDraftPrompt(''));
      dispatch(setSending(true));
      // Simulate latency so the typing indicator is visible.
      await new Promise((r) => setTimeout(r, 600));
      dispatch(
        appendMessage({
          id: `m-${Date.now() + 1}`,
          role: 'assistant',
          content: stubAssistantReply(trimmed),
          createdAt: new Date().toISOString(),
        }),
      );
      dispatch(setSending(false));
    },
    [dispatch],
  );

  return {
    ...state,
    setDraft: (v: string) => dispatch(setDraftPrompt(v)),
    send,
    reset: () => dispatch(resetConversation()),
  };
}
