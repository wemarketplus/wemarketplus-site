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
 * Whether a rejected RTK Query request was refused for authorization rather than
 * failing in a way a retry could fix. Same shape check the owner portal uses
 * (`'status' in error`), kept local because it is the only consumer here.
 */
function isPermissionDenied(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === 'object' &&
      'status' in error &&
      (error as { status?: unknown }).status === 403,
  );
}

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
      } catch (error) {
        // Never invent an answer on failure. Saying nothing useful is correct here;
        // saying something plausible is what the old stub did wrong.
        //
        // But "try again shortly" must be reserved for failures that a retry could
        // actually fix. POST /ai is guarded by @RequirePermission("ai_assistant"),
        // and a tenant whose permission matrix denies the caller's role gets a 403
        // on every single attempt — so telling that user to wait sent them into an
        // endless retry loop over a setting only an admin can change. Observed with
        // a Caregiver on 2026-08-11: the role is allowed by the code default and
        // denied by the tenant's saved override.
        reply = isPermissionDenied(error)
          ? 'Your role does not have access to the AI assistant. An administrator can grant it under Admin → Roles & permissions.'
          : 'The assistant is unavailable right now, so there is no answer to give. Please try again shortly.';
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
