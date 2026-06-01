import { Send, Sparkles } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { AiPresetChips } from '../components/AiPresetChips';
import { AiMessageBubble } from '../components/AiMessageBubble';
import { useAiAssistant } from '../hooks/useAiAssistant';

export function AiAssistantPage() {
  const { conversation, draftPrompt, isSending, setDraft, send } = useAiAssistant();

  return (
    <div className="space-y-6">
      <header className="flex items-start gap-4">
        <div className="flex h-11 w-11 items-center justify-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/20">
          <Sparkles className="h-5 w-5" />
        </div>
        <div>
          <h1 className="font-display text-3xl text-foreground">AI assistant</h1>
          <p className="mt-1 text-sm text-muted">
            Ask about cold sources, draft follow-ups, or strategize on a stuck deal.
          </p>
        </div>
      </header>

      <AiPresetChips onPick={(p) => send(p)} />

      <Card>
        <CardContent className="space-y-4 px-6 py-6">
          {conversation.length === 0 ? (
            <p className="rounded-md border border-dashed border-white/[0.06] px-4 py-8 text-center text-sm text-muted-soft">
              Pick a preset above or type a question below to get started.
            </p>
          ) : (
            <div className="space-y-3">
              {conversation.map((m) => (
                <AiMessageBubble key={m.id} message={m} />
              ))}
              {isSending && (
                <p className="text-xs text-muted-soft">Assistant is thinking…</p>
              )}
            </div>
          )}

          <form
            onSubmit={(e) => {
              e.preventDefault();
              send(draftPrompt);
            }}
            className="flex items-center gap-2"
          >
            <input
              value={draftPrompt}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="Ask anything…"
              className="flex h-11 w-full rounded-md border border-white/10 bg-surface-raised px-3.5 text-sm text-foreground placeholder:text-faint focus-visible:border-azure/70 focus-visible:bg-surface focus-visible:outline-none"
            />
            <Button type="submit" disabled={isSending || !draftPrompt.trim()}>
              <Send className="h-4 w-4" />
              Send
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
