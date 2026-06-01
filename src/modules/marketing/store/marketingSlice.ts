import { createSlice } from '@reduxjs/toolkit';
import type { MarketingUiState } from '../types/marketingTypes';

const initialState: MarketingUiState = { _placeholder: true };

const marketingSlice = createSlice({
  name: 'marketing',
  initialState,
  reducers: {},
});

export default marketingSlice.reducer;
