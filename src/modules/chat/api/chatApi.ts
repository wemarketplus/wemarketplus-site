import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  AiReply,
  ChannelMessage,
  ChatUser,
  DmMessage,
} from '../types/chatTypes';

// Team chat + direct messages + AI assistant — wemarketplus-backend chat, dm, ai.
const env = <T>(res: ApiEnvelope<T>) => res.data;

export const chatApi = createApi({
  reducerPath: 'chatApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ChatMessages', 'DmMessages', 'DmUnread', 'ChatUsers'],
  endpoints: (build) => ({
    // The tenant roster, EXCLUDING the signed-in user (the service filters them
    // out), so this list is exactly "people I can DM".
    listChatUsers: build.query<ChatUser[], void>({
      query: () => ({ url: '/chat/users' }),
      transformResponse: env<ChatUser[]>,
      providesTags: ['ChatUsers'],
    }),
    /**
     * Refreshes the caller's presence and returns how many people are currently
     * online. A query rather than a mutation despite being a POST: it is called on a
     * timer to READ presence, and as a mutation every tick would need a manual
     * dispatch and could not be cached or deduped.
     */
    heartbeat: build.query<{ ok: true; online: number }, void>({
      query: () => ({ url: '/chat/heartbeat', method: 'POST' }),
      transformResponse: env<{ ok: true; online: number }>,
    }),
    /**
     * `limit` only — there is no `before` cursor on ListMessagesDto, and sending one
     * was silently ignored (the DTO whitelists, it does not 400). Oldest-first from
     * the server, which is the order the thread renders.
     */
    listChannelMessages: build.query<
      ChannelMessage[],
      { channel: string; limit?: number }
    >({
      query: ({ channel, ...params }) => ({ url: `/chat/${channel}`, params }),
      transformResponse: env<ChannelMessage[]>,
      // Per-channel, so posting in one does not refetch the other two.
      providesTags: (_r, _e, { channel }) => [
        { type: 'ChatMessages' as const, id: channel },
      ],
    }),
    sendChannelMessage: build.mutation<
      ChannelMessage,
      { channel: string; text: string }
    >({
      query: ({ channel, text }) => ({
        url: `/chat/${channel}`,
        method: 'POST',
        body: { text },
      }),
      transformResponse: env<ChannelMessage>,
      invalidatesTags: (_r, _e, { channel }) => [
        { type: 'ChatMessages' as const, id: channel },
      ],
    }),
    // direct messages
    dmUnreadCounts: build.query<Record<string, number>, void>({
      query: () => ({ url: '/dm/unread-counts' }),
      transformResponse: env<Record<string, number>>,
      providesTags: ['DmUnread'],
    }),
    listDmMessages: build.query<DmMessage[], { userId: string; limit?: number }>({
      query: ({ userId, ...params }) => ({ url: `/dm/${userId}`, params }),
      transformResponse: env<DmMessage[]>,
      providesTags: (_r, _e, { userId }) => [
        { type: 'DmMessages' as const, id: userId },
      ],
    }),
    sendDm: build.mutation<DmMessage, { userId: string; text: string }>({
      query: ({ userId, text }) => ({
        url: `/dm/${userId}`,
        method: 'POST',
        body: { text },
      }),
      transformResponse: env<DmMessage>,
      // The thread AND the unread badges: sending clears nothing for me, but the
      // counts endpoint is the same cache entry the sidebar reads.
      invalidatesTags: (_r, _e, { userId }) => [
        { type: 'DmMessages' as const, id: userId },
        'DmUnread',
      ],
    }),
    // 204 No Content — nothing to transform.
    markDmRead: build.mutation<void, string>({
      query: (userId) => ({ url: `/dm/${userId}/read`, method: 'POST' }),
      invalidatesTags: (_r, _e, userId) => [
        { type: 'DmMessages' as const, id: userId },
        'DmUnread',
      ],
    }),
    // AI assistant
    askAi: build.mutation<AiReply, { prompt: string; context?: string }>({
      query: (body) => ({ url: '/ai', method: 'POST', body }),
      transformResponse: env<AiReply>,
    }),
    /**
     * The Playbook Generator — POST /ai/playbook.
     *
     * Lives beside the other AI calls because it IS the same assistant: same
     * rate limit, same daily quota, same audit trail. Only the system prompt and
     * a per-kind instruction differ, server-side.
     *
     * Gated at Max by `playbook_generator`; a lower tier gets 402, which
     * baseQueryWithReauth already routes to billing.
     */
    generatePlaybook: build.mutation<
      AiReply,
      { kind: string; situation: string; context?: string }
    >({
      query: (body) => ({ url: '/ai/playbook', method: 'POST', body }),
      transformResponse: env<AiReply>,
    }),
    generateNote: build.mutation<AiReply, { prompt: string; context?: string }>({
      query: (body) => ({ url: '/ai/note-generator', method: 'POST', body }),
      transformResponse: env<AiReply>,
    }),
    // Domain-specific AI assists. Bodies are free-form (all-optional, snake_case
    // on the backend); callers pass the relevant record fields.
    aiEmployerAssist: build.mutation<AiReply, Record<string, unknown>>({
      query: (body) => ({ url: '/ai/employer', method: 'POST', body }),
      transformResponse: env<AiReply>,
    }),
    aiApplicationAssist: build.mutation<AiReply, Record<string, unknown>>({
      query: (body) => ({ url: '/ai/application', method: 'POST', body }),
      transformResponse: env<AiReply>,
    }),
    aiCommunicationsAssist: build.mutation<AiReply, Record<string, unknown>>({
      query: (body) => ({ url: '/ai/communications', method: 'POST', body }),
      transformResponse: env<AiReply>,
    }),
  }),
});

export const {
  useListChatUsersQuery,
  useHeartbeatQuery,
  useListChannelMessagesQuery,
  useSendChannelMessageMutation,
  useDmUnreadCountsQuery,
  useListDmMessagesQuery,
  useSendDmMutation,
  useMarkDmReadMutation,
  useAskAiMutation,
  useGeneratePlaybookMutation,
  useGenerateNoteMutation,
  useAiEmployerAssistMutation,
  useAiApplicationAssistMutation,
  useAiCommunicationsAssistMutation,
} = chatApi;
