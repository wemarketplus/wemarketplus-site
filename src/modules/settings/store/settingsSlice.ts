import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { SettingsTab, SettingsUiState } from '../types/settingsTypes';

const initialState: SettingsUiState = { activeTab: 'profile' };

const settingsSlice = createSlice({
  name: 'settings',
  initialState,
  reducers: {
    setActiveTab(state, action: PayloadAction<SettingsTab>) {
      state.activeTab = action.payload;
    },
  },
});

export const { setActiveTab } = settingsSlice.actions;
export default settingsSlice.reducer;
