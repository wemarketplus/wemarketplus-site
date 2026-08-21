import { useEffect, useMemo, useState } from 'react';
import { useAppSelector } from '@/app/hooks';
import {
  useDmUnreadCountsQuery,
  useHeartbeatQuery,
  useListChannelMessagesQuery,
  useListChatUsersQuery,
  useListDmMessagesQuery,
  useMarkDmReadMutation,
  useSendChannelMessageMutation,
  useSendDmMutation,
} from '../api/chatApi';
import {
  CHAT_CHANNELS,
  CHAT_MESSAGES_LIMIT,
  CHAT_POLL_INTERVAL_MS,
} from '../constants/chatConstants';
import { useChatPresence } from './useChatPresence';
import type { ChatRosterEntry, ThreadMessage } from '../types/chatTypes';

/**
 * Which conversation is open. A channel and a person are different endpoints, so the
 * selection is a tagged union rather than one id — that way there is no state in
 * which both or neither is set.
 */
export type Conversation =
  | { kind: 'channel'; id: string }
  | { kind: 'dm'; id: string };

/**
 * Everything the Secure messaging screen needs.
 *
 * WHY THIS SCREEN EXISTS AT ALL: `src/chat` on the backend — channels, direct
 * messages, unread counts, presence — has been complete and gated on the Gold
 * `clinical_secure_messaging` feature key for some time with NO UI in front of it.
 * The sidebar row that said "Secure messaging" actually opened the telehealth
 * session list, so the module was sold and unreachable. This hook and its page are
 * that missing front end; no endpoint was added for them.
 *
 * TWO TRANSPORTS, split by what each actually carries: messages POLL (see
 * CHAT_POLL_INTERVAL_MS) because the backend has no message push, and presence
 * SUBSCRIBES to the SSE stream because that is the only place the online id list
 * exists (see useChatPresence).
 */
export function useSecureMessaging() {
  const myUserId = useAppSelector((s) => s.auth.user?.id ?? null);
  const [conversation, setConversation] = useState<Conversation>({
    kind: 'channel',
    id: CHAT_CHANNELS[0].id,
  });

  const isChannel = conversation.kind === 'channel';

  /**
   * Real presence, from the SSE stream — the only source of the online ID LIST. The
   * heartbeat below is kept for its `online` COUNT, which the stream does not carry,
   * and because polling it keeps this user visible to others on a tenant where the
   * stream connection is refused.
   */
  const onlineIds = useChatPresence(true);
  const { data: presence } = useHeartbeatQuery(undefined, {
    pollingInterval: CHAT_POLL_INTERVAL_MS,
  });

  const { data: users, isLoading: usersLoading } = useListChatUsersQuery();
  const { data: unread } = useDmUnreadCountsQuery(undefined, {
    pollingInterval: CHAT_POLL_INTERVAL_MS,
  });

  const channelQuery = useListChannelMessagesQuery(
    { channel: conversation.id, limit: CHAT_MESSAGES_LIMIT },
    { skip: !isChannel, pollingInterval: CHAT_POLL_INTERVAL_MS },
  );
  const dmQuery = useListDmMessagesQuery(
    { userId: conversation.id, limit: CHAT_MESSAGES_LIMIT },
    { skip: isChannel, pollingInterval: CHAT_POLL_INTERVAL_MS },
  );

  const [sendChannel, channelSendState] = useSendChannelMessageMutation();
  const [sendDm, dmSendState] = useSendDmMutation();
  const [markRead] = useMarkDmReadMutation();

  /**
   * Opening a DM marks it read. Keyed on the thread's newest message rather than
   * just the user id: re-opening a conversation that has since received something
   * new has to clear it again, and an effect that only watched the id would not fire.
   */
  const newestDmId = dmQuery.data?.[dmQuery.data.length - 1]?.id ?? null;
  useEffect(() => {
    if (isChannel || !newestDmId) return;
    void markRead(conversation.id);
  }, [isChannel, conversation.id, newestDmId, markRead]);

  /**
   * The roster, with presence and unread joined in.
   *
   * Sorted so the conversations needing attention come first: unread, then online,
   * then alphabetical. A flat alphabetical list buries the one thread that is
   * actually waiting on you.
   */
  const roster = useMemo<readonly ChatRosterEntry[]>(
    () =>
      (users ?? [])
        .map((user) => ({
          ...user,
          online: onlineIds.has(user.id),
          unread: unread?.[user.id] ?? 0,
        }))
        .sort(
          (a, b) =>
            Number(b.unread > 0) - Number(a.unread > 0) ||
            Number(b.online) - Number(a.online) ||
            a.name.localeCompare(b.name),
        ),
    [users, unread, onlineIds],
  );

  /** Both message kinds, normalised to what the thread renders. */
  const messages = useMemo<readonly ThreadMessage[]>(() => {
    if (isChannel) {
      return (channelQuery.data ?? []).map((message) => ({
        id: message.id,
        authorId: message.userId,
        text: message.text,
        createdAt: message.createdAt,
        // Channel messages carry no `isMine` — the DTO has no such field, so it is
        // derived here. A DM's comes from the server.
        isMine: message.userId === myUserId,
      }));
    }
    return (dmQuery.data ?? []).map((message) => ({
      id: message.id,
      authorId: message.fromUserId,
      text: message.text,
      createdAt: message.createdAt,
      isMine: message.isMine,
    }));
  }, [isChannel, channelQuery.data, dmQuery.data, myUserId]);

  /** id -> display name, for labelling a channel message's author. */
  const nameById = useMemo(() => {
    const map = new Map<string, string>();
    (users ?? []).forEach((user) => map.set(user.id, user.name));
    return map;
  }, [users]);

  const send = async (text: string): Promise<boolean> => {
    const body = text.trim();
    if (!body) return false;
    try {
      if (isChannel) {
        await sendChannel({ channel: conversation.id, text: body }).unwrap();
      } else {
        await sendDm({ userId: conversation.id, text: body }).unwrap();
      }
      return true;
    } catch {
      return false;
    }
  };

  const activeChannel = isChannel
    ? CHAT_CHANNELS.find((channel) => channel.id === conversation.id)
    : undefined;
  const activePerson = isChannel
    ? undefined
    : roster.find((entry) => entry.id === conversation.id);

  return {
    channels: CHAT_CHANNELS,
    roster,
    usersLoading,
    conversation,
    setConversation,
    /** The heading for whichever conversation is open. */
    title: activeChannel ? `# ${activeChannel.label}` : (activePerson?.name ?? 'Direct message'),
    subtitle: activeChannel?.description ?? activePerson?.email ?? '',
    // The stream's list once it has ticked; the heartbeat's count until then.
    onlineCount: onlineIds.size || (presence?.online ?? 0),
    messages,
    nameById,
    isLoading: isChannel ? channelQuery.isLoading : dmQuery.isLoading,
    error: isChannel ? channelQuery.error : dmQuery.error,
    isSending: channelSendState.isLoading || dmSendState.isLoading,
    send,
  };
}
