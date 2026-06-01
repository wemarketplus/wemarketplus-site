import { createSlice } from '@reduxjs/toolkit';
import type { BillingUiState } from '../types/billingTypes';

const initialState: BillingUiState = { _placeholder: true };

// No client UI state today; the slice exists so store wiring stays symmetric
// across modules. Add reducers if we introduce a billing-screen filter, modal,
// etc.
const billingSlice = createSlice({
  name: 'billing',
  initialState,
  reducers: {},
});

export default billingSlice.reducer;
