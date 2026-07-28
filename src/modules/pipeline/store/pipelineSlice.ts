import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import { ProspectPipelineType } from '@/modules/prospects/types/prospectsTypes';
import type { ID } from '@/shared/types';
import type { PipelineUiState } from '../types/pipelineTypes';

const initialState: PipelineUiState = {
  pipelineType: ProspectPipelineType.ReferralToAdmit,
  draggingProspectId: null,
};

const pipelineSlice = createSlice({
  name: 'pipeline',
  initialState,
  reducers: {
    setPipelineType(state, action: PayloadAction<ProspectPipelineType>) {
      state.pipelineType = action.payload;
      // A type switch replaces the whole board, so any in-flight drag is void.
      state.draggingProspectId = null;
    },
    setDragging(state, action: PayloadAction<ID | null>) {
      state.draggingProspectId = action.payload;
    },
  },
});

export const { setPipelineType, setDragging } = pipelineSlice.actions;
export default pipelineSlice.reducer;
