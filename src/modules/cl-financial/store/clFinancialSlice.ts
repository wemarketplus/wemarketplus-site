import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ClFinancialUiState } from '../types/clFinancialTypes';

const initialState: ClFinancialUiState = { view: 'ledger' };

const clFinancialSlice = createSlice({
  name: 'clFinancial',
  initialState,
  reducers: {
    setFinancialView(
      state,
      action: PayloadAction<ClFinancialUiState['view']>,
    ) {
      state.view = action.payload;
    },
  },
});

export const { setFinancialView } = clFinancialSlice.actions;
export default clFinancialSlice.reducer;
