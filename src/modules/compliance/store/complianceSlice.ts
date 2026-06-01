import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ComplianceUiState } from '../types/complianceTypes';

const initialState: ComplianceUiState = { query: '' };

const complianceSlice = createSlice({
  name: 'compliance',
  initialState,
  reducers: {
    setComplianceQuery(state, action: PayloadAction<string>) {
      state.query = action.payload;
    },
  },
});

export const { setComplianceQuery } = complianceSlice.actions;
export default complianceSlice.reducer;
