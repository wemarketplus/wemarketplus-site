import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { AuditLogFilters, ComplianceUiState } from '../types/complianceTypes';

const emptyFilters: AuditLogFilters = {
  action: '',
  resource: '',
  userId: '',
  dateFrom: '',
  dateTo: '',
};

const initialState: ComplianceUiState = {
  query: '',
  filters: emptyFilters,
  page: 1,
};

const complianceSlice = createSlice({
  name: 'compliance',
  initialState,
  reducers: {
    setComplianceQuery(state, action: PayloadAction<string>) {
      state.query = action.payload;
    },
    // Sets one structured filter and resets to the first page so the user sees
    // the start of the newly filtered result set.
    setAuditFilter(
      state,
      action: PayloadAction<{ key: keyof AuditLogFilters; value: string }>,
    ) {
      state.filters[action.payload.key] = action.payload.value;
      state.page = 1;
    },
    clearAuditFilters(state) {
      state.filters = emptyFilters;
      state.query = '';
      state.page = 1;
    },
    setAuditPage(state, action: PayloadAction<number>) {
      state.page = Math.max(1, action.payload);
    },
  },
});

export const {
  setComplianceQuery,
  setAuditFilter,
  clearAuditFilters,
  setAuditPage,
} = complianceSlice.actions;
export default complianceSlice.reducer;
