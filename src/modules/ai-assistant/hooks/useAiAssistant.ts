import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import {
  appendMessage,
  resetConversation,
  setDraftPrompt,
  setSending,
} from '../store/aiAssistantSlice';
import { useAskAiMutation } from '@/modules/chat';
import { generateMessageId } from '../utils/aiAssistantUtils';

/**
 * The AI assistant, talking to the real backend (POST /ai).
 *
 * It previously called a CLIENT-SIDE STUB that returned canned sentences — and not
 * obviously-fake ones: asking about cold accounts produced "Trinity Senior Living
 * and 2 others are overdue. I queued reminders for tomorrow morning." No such
 * accounts, no queued reminders. A marketer would act on that.
 *
 * The backend was already there and fully guarded: it sanitises input, rate-limits
 * per user, meters usage per tenant (ai_usage_daily), audits every call, and
 * degrades gracefully with a plain message when no API key is configured. So this is
 * a rewiring, not a build.
 */
export function useAiAssistant() {
  const dispatch = useAppDispatch();
  const state = useAppSelector((s) => s.aiAssistant);
  const [askAi] = useAskAiMutation();

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
      let reply: string;
      try {
        const result = await askAi({ prompt: trimmed }).unwrap();
        // The backend returns { text } and degrades to an explanatory message with
        // error:true when unconfigured or rate-limited — surface it verbatim rather
        // than substituting something more confident.
        reply =
          result.text ??
          result.reply ??
          'The assistant returned no content. Please try again.';
      } catch {
        // Never invent an answer on failure. Saying nothing useful is correct here;
        // saying something plausible is what the old stub did wrong.
        reply =
          'The assistant is unavailable right now, so there is no answer to give. Please try again shortly.';
      }
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
    [askAi, dispatch],
  );

  return {
    ...state,
    setDraft: (v: string) => dispatch(setDraftPrompt(v)),
    send,
    reset: () => dispatch(resetConversation()),
  };
}
