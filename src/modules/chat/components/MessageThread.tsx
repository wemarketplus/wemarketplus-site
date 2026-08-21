import { useEffect, useRef } from 'react';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import type { ThreadMessage } from '../types/chatTypes';

interface MessageThreadProps {
  messages: readonly ThreadMessage[];
  /** id -> display name, for labelling someone else's message in a channel. */
  nameById: ReadonlyMap<string, string>;
  /** True for a channel: a DM needs no author label, there are only two people. */
  showAuthors: boolean;
  isLoading: boolean;
  hasError: boolean;
}

export function MessageThread({
  messages,
  nameById,
  showAuthors,
  isLoading,
  hasError,
}: MessageThreadProps) {
  const endRef = useRef<HTMLDivElement | null>(null);

  /**
   * Stick to the newest message.
   *
   * Keyed on the last message id rather than `messages`, which is a fresh array on
   * every poll tick — scrolling on each of those would fight a user who has
   * deliberately scrolled up to read back.
   */
  const lastId = messages[messages.length - 1]?.id ?? null;
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' });
  }, [lastId]);

  if (isLoading) {
    return <p className="p-4 text-[13px] text-muted-soft">Loading messages…</p>;
  }
  if (hasError) {
    return (
      <p className="p-4 text-[13px] text-destructive">
        Could not load this conversation.
      </p>
    );
  }
  if (messages.length === 0) {
    return (
      <p className="p-4 text-[13px] text-muted-soft">
        No messages yet — say something to start this conversation.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3 p-4">
      {messages.map((message) => (
        <article
          key={message.id}
          className={[
            'max-w-[80%] rounded-lg px-3 py-2',
            message.isMine
              ? 'self-end bg-primary/20'
              : 'self-start bg-surface-2',
          ].join(' ')}
        >
          {showAuthors && !message.isMine && (
            <p className="mb-0.5 text-[11px] font-semibold text-muted">
              {nameById.get(message.authorId) ?? 'Teammate'}
            </p>
          )}
          {/* pre-wrap: a handover note is written with line breaks and they carry
              meaning. */}
          <p className="whitespace-pre-wrap break-words text-[13px] text-foreground">
            {message.text}
          </p>
          <time
            dateTime={message.createdAt}
            className="mt-1 block text-[10px] text-muted-soft"
          >
            {formatDateTime(message.createdAt)}
          </time>
        </article>
      ))}
      <div ref={endRef} />
    </div>
  );
}
