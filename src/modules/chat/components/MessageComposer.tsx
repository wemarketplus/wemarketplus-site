import { useState } from 'react';
import { SendHorizontal } from 'lucide-react';
import { Button, Textarea } from '@/shared/ui/core';
import { CHAT_TEXT_MAX_LENGTH } from '../constants/chatConstants';

interface MessageComposerProps {
  isSending: boolean;
  /** Names the conversation, so the placeholder says where this is going. */
  targetLabel: string;
  onSend: (text: string) => Promise<boolean>;
}

export function MessageComposer({
  isSending,
  targetLabel,
  onSend,
}: MessageComposerProps) {
  const [text, setText] = useState('');

  const submit = async () => {
    const body = text.trim();
    if (!body || isSending) return;
    const ok = await onSend(body);
    // Cleared only on success, so a failed send does not lose what was typed.
    if (ok) setText('');
  };

  /**
   * Enter sends, Shift+Enter makes a newline — the convention every messaging tool
   * uses, and the reason the composer is a textarea rather than an input: a shift
   * handover legitimately runs to several lines.
   */
  const onKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      void submit();
    }
  };

  const remaining = CHAT_TEXT_MAX_LENGTH - text.length;

  return (
    <div className="border-t border-border p-3">
      <div className="flex items-end gap-2">
        <Textarea
          rows={2}
          value={text}
          // Enforced client-side to match the backend's @MaxLength: being stopped
          // at the limit is kinder than a 400 after writing a long note.
          maxLength={CHAT_TEXT_MAX_LENGTH}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder={`Message ${targetLabel}`}
          aria-label={`Message ${targetLabel}`}
          className="flex-1 resize-none"
        />
        <Button
          onClick={submit}
          disabled={isSending || text.trim().length === 0}
          aria-label="Send message"
        >
          {isSending ? 'Sending…' : <SendHorizontal className="size-4" aria-hidden />}
        </Button>
      </div>
      <div className="mt-1 flex items-center justify-between text-[11px] text-muted-soft">
        <span>Enter to send · Shift+Enter for a new line</span>
        {/* Surfaced only near the ceiling — a permanent counter is noise. */}
        {remaining < 200 && <span>{remaining} characters left</span>}
      </div>
    </div>
  );
}
