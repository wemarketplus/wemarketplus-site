import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { SchedulingUiState } from '../types/schedulingTypes';

const initialState: SchedulingUiState = { view: 'territories' };

const schedulingSlice = createSlice({
  name: 'scheduling',
  initialState,
  reducers: {
    setSchedulingView(state, action: PayloadAction<SchedulingUiState['view']>) {
      state.view = action.payload;
    },
  },
});

export const { setSchedulingView } = schedulingSlice.actions;
export default schedulingSlice.reducer;
