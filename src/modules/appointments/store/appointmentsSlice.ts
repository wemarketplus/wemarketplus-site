import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type {
  AppointmentStatus,
  AppointmentsUiState,
} from '../types/appointmentsTypes';

const initialState: AppointmentsUiState = { statusFilter: 'all' };

const appointmentsSlice = createSlice({
  name: 'appointments',
  initialState,
  reducers: {
    setAppointmentStatusFilter(
      state,
      action: PayloadAction<AppointmentStatus | 'all'>,
    ) {
      state.statusFilter = action.payload;
    },
  },
});

export const { setAppointmentStatusFilter } = appointmentsSlice.actions;
export default appointmentsSlice.reducer;
