import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { IntegrationsUiState } from '../types/integrationsTypes';

const initialState: IntegrationsUiState = { category: 'all' };

const integrationsSlice = createSlice({
  name: 'integrations',
  initialState,
  reducers: {
    setIntegrationCategory(
      state,
      action: PayloadAction<IntegrationsUiState['category']>,
    ) {
      state.category = action.payload;
    },
  },
});

export const { setIntegrationCategory } = integrationsSlice.actions;
export default integrationsSlice.reducer;
