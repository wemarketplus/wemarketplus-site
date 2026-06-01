import { createSlice } from '@reduxjs/toolkit';
import type { DashboardUiState } from '../types/dashboardTypes';

const initialState: DashboardUiState = { _placeholder: true };

// Slice exists to keep store wiring symmetric across modules. Add real reducers
// (date range, selected segment, etc.) when the dashboard grows controls.
const dashboardSlice = createSlice({
  name: 'dashboard',
  initialState,
  reducers: {},
});

export default dashboardSlice.reducer;
