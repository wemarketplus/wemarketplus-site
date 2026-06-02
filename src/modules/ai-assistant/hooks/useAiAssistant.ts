import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import {
  appendMessage,
  resetConversation,
  setDraftPrompt,
  setSending,
} from '../store/aiAssistantSlice';
import { sendAiMessage } from '../api/aiAssistantApi';
import { generateMessageId } from '../utils/aiAssistantUtils';

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
          id: generateMessageId(),
          role: 'user',
          content: trimmed,
          createdAt: now,
        }),
      );
      dispatch(setDraftPrompt(''));
      dispatch(setSending(true));
      const reply = await sendAiMessage(trimmed);
      dispatch(
        appendMessage({
          id: generateMessageId(),
          role: 'assistant',
          content: reply,
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
