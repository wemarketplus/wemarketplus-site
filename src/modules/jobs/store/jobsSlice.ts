import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { JobStatus, JobType, JobsUiState } from '../types/jobsTypes';

const initialState: JobsUiState = { statusFilter: 'all', typeFilter: 'all' };

const jobsSlice = createSlice({
  name: 'jobs',
  initialState,
  reducers: {
    setJobStatusFilter(state, action: PayloadAction<JobStatus | 'all'>) {
      state.statusFilter = action.payload;
    },
    setJobTypeFilter(state, action: PayloadAction<JobType | 'all'>) {
      state.typeFilter = action.payload;
    },
  },
});

export const { setJobStatusFilter, setJobTypeFilter } = jobsSlice.actions;
export default jobsSlice.reducer;
