import type { ID, ISODateString } from '@/shared/types';

// Team chat + direct messages + AI assistant — wemarketplus-backend chat, dm, ai.
export interface ChatUser {
  id: ID;
  firstName: string;
  lastName: string;
  online?: boolean;
}

export interface ChatMessage {
  id: ID;
  channel?: string;
  fromUserId: ID;
  toUserId?: ID;
  text: string;
  createdAt: ISODateString;
}

export interface AiReply {
  reply?: string;
  text?: string;
  [key: string]: unknown;
}
