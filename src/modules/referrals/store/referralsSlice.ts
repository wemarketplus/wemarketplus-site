import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ReferralSourceStatus } from '@/shared/types';
import type { ReferralsUiState } from '../types/referralsTypes';

const initialState: ReferralsUiState = {
  search: '',
  statusFilter: 'all',
};

const referralsSlice = createSlice({
  name: 'referrals',
  initialState,
  reducers: {
    setReferralSearch(state, action: PayloadAction<string>) {
      state.search = action.payload;
    },
    setReferralStatusFilter(
      state,
      action: PayloadAction<ReferralSourceStatus | 'all'>,
    ) {
      state.statusFilter = action.payload;
    },
  },
});

export const { setReferralSearch, setReferralStatusFilter } =
  referralsSlice.actions;
export default referralsSlice.reducer;
