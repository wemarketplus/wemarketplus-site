import { createSlice } from '@reduxjs/toolkit';
import type { ClReferralsUiState } from '../types/clReferralsTypes';

const initialState: ClReferralsUiState = { _placeholder: true };

const clReferralsSlice = createSlice({
  name: 'clReferrals',
  initialState,
  reducers: {},
});

export default clReferralsSlice.reducer;
