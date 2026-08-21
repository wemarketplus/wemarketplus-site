import { ShieldCheck } from 'lucide-react';
import { Card } from '@/shared/ui/core';
import { ConversationList } from '../components/ConversationList';
import { MessageComposer } from '../components/MessageComposer';
import { MessageThread } from '../components/MessageThread';
import { useSecureMessaging } from '../hooks/useSecureMessaging';

/**
 * Secure messaging — staff channels and direct messages.
 *
 * THE UI FOR A BACKEND THAT SHIPPED WITHOUT ONE. `src/chat` (channels, DMs, unread
 * counts, presence) has been complete and gated on the Gold
 * `clinical_secure_messaging` feature key, while the sidebar row named "Secure
 * messaging" actually opened the care-team telehealth session list. The row was
 * renamed to match what it opened, with the note that building this screen was a
 * feature rather than a rename; this is that feature. Nothing was added to the API.
 *
 * NOT the same thing as Family communication (/clinical/family), which is a
 * compliance LOG of conversations held with a patient's family, or as Care-team
 * telehealth, which is scheduled video. This is staff-to-staff text.
 */
export function SecureMessagingPage() {
  const {
    channels,
    roster,
    usersLoading,
    conversation,
    setConversation,
    title,
    subtitle,
    onlineCount,
    messages,
    nameById,
    isLoading,
    error,
    isSending,
    send,
  } = useSecureMessaging();

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold text-foreground">Secure messaging</h1>
          <p className="text-[13px] text-muted">
            Team channels and direct messages, inside your agency.
          </p>
        </div>
        <p className="flex items-center gap-1.5 text-[12px] text-muted-soft">
          <ShieldCheck className="size-3.5" aria-hidden />
          {onlineCount} online
        </p>
      </header>

      {/* Fixed-height grid so the thread scrolls inside the card rather than
          growing the page — a long channel history should not push the composer
          off the bottom of the screen. */}
      <div className="grid gap-4 lg:grid-cols-[220px_1fr]">
        <Card className="p-3">
          <ConversationList
            channels={channels}
            roster={roster}
            usersLoading={usersLoading}
            active={conversation}
            onSelect={setConversation}
          />
        </Card>

        <Card className="flex h-[min(70vh,640px)] flex-col overflow-hidden">
          <div className="border-b border-border px-4 py-3">
            <h2 className="text-[14px] font-semibold text-foreground">{title}</h2>
            {subtitle && (
              <p className="text-[12px] text-muted-soft">{subtitle}</p>
            )}
          </div>

          <div className="flex-1 overflow-y-auto">
            <MessageThread
              messages={messages}
              nameById={nameById}
              showAuthors={conversation.kind === 'channel'}
              isLoading={isLoading}
              hasError={Boolean(error)}
            />
          </div>

          <MessageComposer
            isSending={isSending}
            targetLabel={title}
            onSend={send}
          />
        </Card>
      </div>
    </div>
  );
}
