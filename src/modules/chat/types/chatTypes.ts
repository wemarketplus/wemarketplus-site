import type { ID, ISODateString } from '@/shared/types';

// Team chat + direct messages + AI assistant — wemarketplus-backend chat, dm, ai.

/**
 * A roster entry from GET /chat/users.
 *
 * Mirrors the backend `ChatUserResponseDto`, which is `{ id, name, email }` — a
 * single pre-joined `name`, not the `firstName`/`lastName` pair this interface used
 * to declare. The old shape was never exercised (nothing rendered chat), so it went
 * unnoticed; rendering `user.firstName` against this endpoint yields `undefined`.
 *
 * `online` is NOT part of the DTO. Presence lives on its own channel (the SSE
 * stream's `presence` event and the heartbeat's `online` count), so it is joined in
 * by the client — see `ChatRosterEntry`.
 */
export interface ChatUser {
  id: ID;
  name: string;
  email: string;
}

/** A roster entry with the client-side presence join applied. */
export interface ChatRosterEntry extends ChatUser {
  online: boolean;
  /** Unread DMs from this person, from GET /dm/unread-counts. */
  unread: number;
}

/**
 * A channel message from GET/POST /chat/:channel.
 *
 * Author is `userId`. Deliberately a DIFFERENT field from a DM's `fromUserId` —
 * the two endpoints return different entities and the old single `ChatMessage`
 * interface papered over that with an optional of each, which silently renders a
 * blank author whichever one you guess wrong.
 */
export interface ChannelMessage {
  id: ID;
  tenantId: ID;
  channel: string;
  userId: ID;
  text: string;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

/** A direct message from GET/POST /dm/:userId. */
export interface DmMessage {
  id: ID;
  tenantId: ID;
  fromUserId: ID;
  toUserId: ID;
  text: string;
  readAt: ISODateString | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  /** Server-computed: true when the signed-in user is the sender. */
  isMine: boolean;
}

/**
 * The shape the thread view renders, which both message kinds normalise into.
 *
 * `authorId` is whichever id the source carried, and `isMine` is server-supplied
 * for a DM but derived from the signed-in user for a channel message (the channel
 * DTO has no such field).
 */
export interface ThreadMessage {
  id: ID;
  authorId: ID;
  text: string;
  createdAt: ISODateString;
  isMine: boolean;
}

export interface AiReply {
  reply?: string;
  text?: string;
  [key: string]: unknown;
}
