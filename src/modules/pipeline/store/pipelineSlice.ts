import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { PipelineUiState } from '../types/pipelineTypes';

const initialState: PipelineUiState = { groupBy: 'status' };

const pipelineSlice = createSlice({
  name: 'pipeline',
  initialState,
  reducers: {
    setGroupBy(state, action: PayloadAction<PipelineUiState['groupBy']>) {
      state.groupBy = action.payload;
    },
  },
});

export const { setGroupBy } = pipelineSlice.actions;
export default pipelineSlice.reducer;
