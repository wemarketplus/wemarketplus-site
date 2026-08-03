import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { AiReply, ChatMessage, ChatUser } from '../types/chatTypes';

// Team chat + direct messages + AI assistant — wemarketplus-backend chat, dm, ai.
const env = <T>(res: ApiEnvelope<T>) => res.data;

export const chatApi = createApi({
  reducerPath: 'chatApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ChatMessages', 'DmMessages'],
  endpoints: (build) => ({
    listChatUsers: build.query<ChatUser[], void>({
      query: () => ({ url: '/chat/users' }),
      transformResponse: env<ChatUser[]>,
    }),
    heartbeat: build.mutation<void, void>({
      query: () => ({ url: '/chat/heartbeat', method: 'POST' }),
    }),
    listChannelMessages: build.query<ChatMessage[], { channel: string; before?: string; limit?: number }>({
      query: ({ channel, ...params }) => ({ url: `/chat/${channel}`, params }),
      transformResponse: (res: ApiEnvelope<ChatMessage[] | { data: ChatMessage[] }>) =>
        Array.isArray(res.data) ? res.data : res.data.data,
      providesTags: ['ChatMessages'],
    }),
    sendChannelMessage: build.mutation<ChatMessage, { channel: string; text: string }>({
      query: ({ channel, text }) => ({ url: `/chat/${channel}`, method: 'POST', body: { text } }),
      transformResponse: env<ChatMessage>,
      invalidatesTags: ['ChatMessages'],
    }),
    // direct messages
    dmUnreadCounts: build.query<Record<string, number>, void>({
      query: () => ({ url: '/dm/unread-counts' }),
      transformResponse: env<Record<string, number>>,
      providesTags: ['DmMessages'],
    }),
    listDmMessages: build.query<ChatMessage[], { userId: string; before?: string; limit?: number }>({
      query: ({ userId, ...params }) => ({ url: `/dm/${userId}`, params }),
      transformResponse: (res: ApiEnvelope<ChatMessage[] | { data: ChatMessage[] }>) =>
        Array.isArray(res.data) ? res.data : res.data.data,
      providesTags: ['DmMessages'],
    }),
    sendDm: build.mutation<ChatMessage, { userId: string; text: string }>({
      query: ({ userId, text }) => ({ url: `/dm/${userId}`, method: 'POST', body: { text } }),
      transformResponse: env<ChatMessage>,
      invalidatesTags: ['DmMessages'],
    }),
    markDmRead: build.mutation<void, string>({
      query: (userId) => ({ url: `/dm/${userId}/read`, method: 'POST' }),
      invalidatesTags: ['DmMessages'],
    }),
    // AI assistant
    askAi: build.mutation<AiReply, { prompt: string; context?: string }>({
      query: (body) => ({ url: '/ai', method: 'POST', body }),
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
  useHeartbeatMutation,
  useListChannelMessagesQuery,
  useSendChannelMessageMutation,
  useDmUnreadCountsQuery,
  useListDmMessagesQuery,
  useSendDmMutation,
  useMarkDmReadMutation,
  useAskAiMutation,
  useGenerateNoteMutation,
  useAiEmployerAssistMutation,
  useAiApplicationAssistMutation,
  useAiCommunicationsAssistMutation,
} = chatApi;
