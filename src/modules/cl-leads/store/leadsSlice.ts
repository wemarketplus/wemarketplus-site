import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { Lead, LeadStatus } from '@/shared/types';
import type { LeadsUiState, NewLeadInput } from '../types/leadsTypes';

const initialState: LeadsUiState = {
  statusFilter: 'all',
  added: [],
  statusOverrides: {},
  addModalOpen: false,
};

const leadsSlice = createSlice({
  name: 'clLeads',
  initialState,
  reducers: {
    setLeadStatusFilter(state, action: PayloadAction<LeadStatus | 'all'>) {
      state.statusFilter = action.payload;
    },
    openAddLead(state) {
      state.addModalOpen = true;
    },
    closeAddLead(state) {
      state.addModalOpen = false;
    },
    addLead(state, action: PayloadAction<NewLeadInput>) {
      const lead: Lead = {
        id: `lead-${Date.now()}`,
        ...action.payload,
      };
      state.added.unshift(lead);
      state.addModalOpen = false;
    },
    updateLeadStatus(
      state,
      action: PayloadAction<{ id: string; status: LeadStatus }>,
    ) {
      state.statusOverrides[action.payload.id] = action.payload.status;
    },
  },
});

export const {
  setLeadStatusFilter,
  openAddLead,
  closeAddLead,
  addLead,
  updateLeadStatus,
} = leadsSlice.actions;
export default leadsSlice.reducer;
