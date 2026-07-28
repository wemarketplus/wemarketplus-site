import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { LeadSourceType, LeadStatus, LeadsUiState } from '../types/leadsTypes';

const initialState: LeadsUiState = {
  search: '',
  statusFilter: 'all',
  sourceFilter: 'all',
};

const leadsSlice = createSlice({
  name: 'leads',
  initialState,
  reducers: {
    setSearch(state, action: PayloadAction<string>) {
      state.search = action.payload;
    },
    setStatusFilter(state, action: PayloadAction<LeadStatus | 'all'>) {
      state.statusFilter = action.payload;
    },
    setSourceFilter(state, action: PayloadAction<LeadSourceType | 'all'>) {
      state.sourceFilter = action.payload;
    },
  },
});

export const { setSearch, setStatusFilter, setSourceFilter } =
  leadsSlice.actions;
export default leadsSlice.reducer;
