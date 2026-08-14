import { useState } from 'react';
import { Send, Sparkles, X } from 'lucide-react';
import { useActiveProduct } from '@/modules/access';
import { CL_FIELD_ROLES, useRole } from '@/shared/rbac';
import { Product } from '@/shared/types';
import { Button } from '@/shared/ui/core';
import { AI_FIELD_PRESETS } from '../constants/aiPresetsConstants';
import { useAiAssistant } from '../hooks/useAiAssistant';
import { AiMessageBubble } from './AiMessageBubble';

/**
 * Copilot — the floating AI helper for a CommunityLink field technician.
 *
 * "On some plans you may see a floating 'Copilot' button — that's an AI helper you
 * can ask maintenance-related questions."
 *
 * WHY A FLOATING BUTTON AND NOT A NAV ROW. Every other CommunityLink persona reaches
 * the assistant through the "AI sales assistant" row, which is CL_SALES_ROLES — the
 * field roles are not in it, and should not be: that screen's presets and copy are
 * about referral sources and pending admissions. Their guide promises a floating
 * button instead, and it fits the surface it floats over: a technician standing in a
 * unit with a queue open asks a question without navigating away from the ticket.
 *
 * SAME BACKEND, SAME GUARDS. It drives `useAiAssistant`, so this is POST /ai with the
 * existing sanitisation, per-user rate limit, per-tenant metering and audit trail —
 * a new entry point, not a second assistant. It also inherits that hook's honest
 * failure handling, which matters more here than on the page: `ai_assistant` is
 * subject to per-tenant permission overrides, so a community that denies this role
 * gets the "an administrator can grant it" message rather than a retry loop. That
 * override is also what makes the guide's "on some plans" true — the capability
 * itself is available at every tier (FEATURE_RANK.ai_assistant = 1), so there is
 * deliberately no tier gate here to contradict it.
 *
 * NOT A <dialog>, and no confirm/alert anywhere: a modal would cover the queue the
 * question is about. It is a corner panel that leaves the page readable behind it.
 */
export function CopilotLauncher() {
  const [open, setOpen] = useState(false);
  const { activeProduct } = useActiveProduct();
  const { isAny } = useRole();
  const { conversation, draftPrompt, isSending, setDraft, send } =
    useAiAssistant();

  // Field roles, CommunityLink only. Everyone else has the nav row, and rendering
  // both for one person would be two doors into one conversation.
  if (activeProduct !== Product.CommunityLink || !isAny(CL_FIELD_ROLES)) {
    return null;
  }

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-40 inline-flex items-center gap-2 rounded-pill bg-primary px-4 py-3 text-sm font-semibold text-primary-foreground shadow-lg transition-transform hover:scale-[1.03] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50"
      >
        <Sparkles className="h-4 w-4" />
        Copilot
      </button>
    );
  }

  return (
    <section
      aria-label="Copilot"
      className="fixed bottom-6 right-6 z-40 flex max-h-[70vh] w-[min(22rem,calc(100vw-3rem))] flex-col overflow-hidden rounded-[14px] border border-border/[0.12] bg-surface shadow-2xl"
    >
      <header className="flex items-center gap-2 border-b border-border/[0.08] px-4 py-3">
        <span className="rounded-[9px] bg-primary/[0.10] p-1.5 text-primary">
          <Sparkles className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-foreground">Copilot</p>
          <p className="text-[11px] text-muted-soft">
            Ask a maintenance question
          </p>
        </div>
        <Button
          variant="ghost"
          size="square"
          onClick={() => setOpen(false)}
          aria-label="Close Copilot"
        >
          <X className="h-4 w-4 text-muted" />
        </Button>
      </header>

      {/* Scrolls inside its own box so the panel cannot grow past the viewport and
          push its own input off screen. */}
      <div className="flex-1 space-y-3 overflow-y-auto px-4 py-3">
        {conversation.length === 0 ? (
          <div className="space-y-3">
            <p className="text-xs text-muted">
              Pick a starting point, or type your own question.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {AI_FIELD_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => send(preset.prompt)}
                  className="rounded-pill border border-border/[0.12] px-2.5 py-1 text-[11px] font-semibold text-muted transition-colors hover:border-primary/40 hover:text-primary"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {conversation.map((message) => (
              <AiMessageBubble key={message.id} message={message} />
            ))}
            {isSending && (
              <p className="text-xs text-muted-soft">Copilot is thinking…</p>
            )}
          </>
        )}
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          send(draftPrompt);
        }}
        className="flex items-center gap-2 border-t border-border/[0.08] px-3 py-3"
      >
        <input
          value={draftPrompt}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Ask anything…"
          aria-label="Ask Copilot"
          className="flex h-10 w-full rounded-md border border-border/10 bg-surface-raised px-3 text-sm text-foreground placeholder:text-faint focus-visible:border-azure/70 focus-visible:bg-surface focus-visible:outline-none"
        />
        <Button
          type="submit"
          size="square"
          disabled={isSending || !draftPrompt.trim()}
          aria-label="Send"
        >
          <Send className="h-4 w-4" />
        </Button>
      </form>
    </section>
  );
}
