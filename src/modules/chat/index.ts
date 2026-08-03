// Team chat + DM + AI assistant — API-only module (no page UI yet).
export {
  chatApi,
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
} from './api/chatApi';
export type { ChatUser, ChatMessage, AiReply } from './types/chatTypes';
