import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ActivityUiState } from '../types/activityTypes';

const initialState: ActivityUiState = { activeTab: 'calendar' };

const activitySlice = createSlice({
  name: 'activity',
  initialState,
  reducers: {
    setActivityTab(state, action: PayloadAction<ActivityUiState['activeTab']>) {
      state.activeTab = action.payload;
    },
  },
});

export const { setActivityTab } = activitySlice.actions;
export default activitySlice.reducer;
