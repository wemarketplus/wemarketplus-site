// Secure messaging (staff channels + DMs) and the AI assistant client.
export {
  chatApi,
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
} from './api/chatApi';
export { SecureMessagingPage } from './pages/SecureMessagingPage';
export { useSecureMessaging, type Conversation } from './hooks/useSecureMessaging';
export { useChatPresence } from './hooks/useChatPresence';
export { CHAT_CHANNELS } from './constants/chatConstants';
export type {
  AiReply,
  ChannelMessage,
  ChatRosterEntry,
  ChatUser,
  DmMessage,
  ThreadMessage,
} from './types/chatTypes';
