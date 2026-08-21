/**
 * Secure messaging constants. Mirrors wemarketplus-backend/src/chat/chat.constants.ts
 * where a value is shared; the channel list is client-side only (see below).
 */

/** Matches CHAT_TEXT_MAX_LENGTH — the composer stops the user before the 400 does. */
export const CHAT_TEXT_MAX_LENGTH = 4000;

/** Matches CHAT_MESSAGES_DEFAULT_LIMIT. The backend caps at 200. */
export const CHAT_MESSAGES_LIMIT = 60;

/**
 * How often the open conversation re-fetches, in ms.
 *
 * POLLED, NOT PUSHED, and deliberately: the backend's SSE stream carries PRESENCE
 * ONLY — `ChatService.stream` emits a `presence` event on a timer and its own
 * comment says "real-time message delivery is left to the client". So there is no
 * message push to subscribe to, and a stream connection would buy a live dot beside
 * a name while messages still arrived on a poll. One poll drives both.
 *
 * 15s rather than something snappier because this is a staff coordination tool, not
 * a consumer chat: the cost of a tighter loop is a request per user per interval
 * against a list endpoint that is not paginated by cursor.
 */
export const CHAT_POLL_INTERVAL_MS = 15_000;

/**
 * The channels offered in the sidebar.
 *
 * DEFINED HERE because the backend has no channel registry: `POST /chat/:channel`
 * accepts any string up to CHANNEL_MAX_LENGTH and creates the channel implicitly on
 * first post. That makes a fixed client-side list the only thing standing between
 * "the team has three shared rooms" and "everyone invents their own channel name and
 * nobody reads the same one". Adding a channel is a one-line change here.
 *
 * Keep the `id` values stable — they ARE the storage key. Renaming an id orphans
 * every message posted under the old one.
 */
export const CHAT_CHANNELS: ReadonlyArray<{
  id: string;
  label: string;
  description: string;
}> = [
  {
    id: 'general',
    label: 'General',
    description: 'Whole-team announcements and anything that is not clinical.',
  },
  {
    id: 'clinical',
    label: 'Clinical',
    description: 'Care coordination across the nursing and caregiving team.',
  },
  {
    id: 'on-call',
    label: 'On-call',
    description: 'Handovers and anything the on-call staff must see.',
  },
];
