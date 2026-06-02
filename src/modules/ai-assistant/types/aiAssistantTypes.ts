export interface AiMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  createdAt: string;
}

export interface AiPreset {
  id: string;
  label: string;
  prompt: string;
}

export interface AiAssistantUiState {
  draftPrompt: string;
  conversation: AiMessage[];
  isSending: boolean;
}

export interface AiMessageBubbleProps {
  message: AiMessage;
}

export interface AiPresetChipsProps {
  onPick: (prompt: string) => void;
}
