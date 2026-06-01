import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { AiAssistantUiState, AiMessage } from '../types/aiAssistantTypes';

const initialState: AiAssistantUiState = {
  draftPrompt: '',
  conversation: [],
  isSending: false,
};

const aiAssistantSlice = createSlice({
  name: 'aiAssistant',
  initialState,
  reducers: {
    setDraftPrompt(state, action: PayloadAction<string>) {
      state.draftPrompt = action.payload;
    },
    appendMessage(state, action: PayloadAction<AiMessage>) {
      state.conversation.push(action.payload);
    },
    setSending(state, action: PayloadAction<boolean>) {
      state.isSending = action.payload;
    },
    resetConversation(state) {
      state.conversation = [];
      state.draftPrompt = '';
    },
  },
});

export const { setDraftPrompt, appendMessage, setSending, resetConversation } =
  aiAssistantSlice.actions;
export default aiAssistantSlice.reducer;
