import { createSlice } from '@reduxjs/toolkit';
import type { ClReportsUiState } from '../types/clReportsTypes';

const initialState: ClReportsUiState = { _placeholder: true };

const clReportsSlice = createSlice({
  name: 'clReports',
  initialState,
  reducers: {},
});

export default clReportsSlice.reducer;
