import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { IntelligenceUiState } from '../types/intelligenceTypes';

const initialState: IntelligenceUiState = { range: '30d' };

const intelligenceSlice = createSlice({
  name: 'intelligence',
  initialState,
  reducers: {
    setIntelligenceRange(
      state,
      action: PayloadAction<IntelligenceUiState['range']>,
    ) {
      state.range = action.payload;
    },
  },
});

export const { setIntelligenceRange } = intelligenceSlice.actions;
export default intelligenceSlice.reducer;
