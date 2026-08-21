import { Hash, Users } from 'lucide-react';
import type { Conversation } from '../hooks/useSecureMessaging';
import type { ChatRosterEntry } from '../types/chatTypes';

interface ConversationListProps {
  channels: ReadonlyArray<{ id: string; label: string; description: string }>;
  roster: readonly ChatRosterEntry[];
  usersLoading: boolean;
  active: Conversation;
  onSelect: (next: Conversation) => void;
}

const isActive = (active: Conversation, kind: Conversation['kind'], id: string) =>
  active.kind === kind && active.id === id;

const rowClass = (selected: boolean) =>
  [
    'flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-[13px] transition-colors',
    selected
      ? 'bg-primary/15 text-foreground'
      : 'text-muted hover:bg-surface-2 hover:text-foreground',
  ].join(' ');

/**
 * The channel + people sidebar.
 *
 * Channels come from a fixed client-side list (CHAT_CHANNELS) because the backend
 * creates a channel implicitly on first post and has no registry to read.
 */
export function ConversationList({
  channels,
  roster,
  usersLoading,
  active,
  onSelect,
}: ConversationListProps) {
  return (
    <nav className="flex flex-col gap-4" aria-label="Conversations">
      <div>
        <p className="mb-1 px-2 text-[11px] font-semibold uppercase tracking-wide text-muted-soft">
          Channels
        </p>
        <ul className="space-y-0.5">
          {channels.map((channel) => (
            <li key={channel.id}>
              <button
                type="button"
                onClick={() => onSelect({ kind: 'channel', id: channel.id })}
                className={rowClass(isActive(active, 'channel', channel.id))}
                aria-current={
                  isActive(active, 'channel', channel.id) ? 'true' : undefined
                }
              >
                <Hash className="size-3.5 shrink-0" aria-hidden />
                <span className="truncate">{channel.label}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>

      <div>
        <p className="mb-1 px-2 text-[11px] font-semibold uppercase tracking-wide text-muted-soft">
          Direct messages
        </p>
        {usersLoading && (
          <p className="px-2 text-[12px] text-muted-soft">Loading team…</p>
        )}
        {!usersLoading && roster.length === 0 && (
          <p className="px-2 text-[12px] text-muted-soft">
            No one else on this team yet.
          </p>
        )}
        <ul className="space-y-0.5">
          {roster.map((person) => (
            <li key={person.id}>
              <button
                type="button"
                onClick={() => onSelect({ kind: 'dm', id: person.id })}
                className={rowClass(isActive(active, 'dm', person.id))}
                aria-current={
                  isActive(active, 'dm', person.id) ? 'true' : undefined
                }
              >
                {/* Presence dot. `title` rather than text so the row stays one
                    line; the aria-label carries it for a screen reader. */}
                <span
                  className={[
                    'size-2 shrink-0 rounded-full',
                    person.online ? 'bg-emerald-500' : 'bg-muted-soft/40',
                  ].join(' ')}
                  aria-label={person.online ? 'Online' : 'Offline'}
                  title={person.online ? 'Online' : 'Offline'}
                />
                <span className="truncate">{person.name}</span>
                {person.unread > 0 && (
                  <span
                    className="ml-auto shrink-0 rounded-full bg-primary px-1.5 text-[11px] font-semibold text-primary-foreground"
                    aria-label={`${person.unread} unread`}
                  >
                    {person.unread}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      </div>

      <p className="flex items-center gap-1.5 px-2 text-[11px] text-muted-soft">
        <Users className="size-3" aria-hidden />
        Messages stay inside your agency.
      </p>
    </nav>
  );
}
