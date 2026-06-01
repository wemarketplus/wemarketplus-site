import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ProspectStatus, Urgency } from '@/shared/types';
import type { ProspectsUiState } from '../types/prospectsTypes';

const initialState: ProspectsUiState = {
  search: '',
  statusFilter: 'all',
  urgencyFilter: 'all',
};

const prospectsSlice = createSlice({
  name: 'prospects',
  initialState,
  reducers: {
    setProspectSearch(state, action: PayloadAction<string>) {
      state.search = action.payload;
    },
    setStatusFilter(state, action: PayloadAction<ProspectStatus | 'all'>) {
      state.statusFilter = action.payload;
    },
    setUrgencyFilter(state, action: PayloadAction<Urgency | 'all'>) {
      state.urgencyFilter = action.payload;
    },
  },
});

export const { setProspectSearch, setStatusFilter, setUrgencyFilter } =
  prospectsSlice.actions;
export default prospectsSlice.reducer;
