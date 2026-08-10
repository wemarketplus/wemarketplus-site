import { createSlice, type PayloadAction } from '@reduxjs/toolkit';
import type { ReferralSourceStatus } from '@/shared/types';
import type { ReferralsUiState } from '../types/referralsTypes';

const initialState: ReferralsUiState = {
  search: '',
  statusFilter: 'all',
  coldOnly: false,
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
    setReferralColdOnly(state, action: PayloadAction<boolean>) {
      state.coldOnly = action.payload;
    },
  },
});

export const {
  setReferralSearch,
  setReferralStatusFilter,
  setReferralColdOnly,
} = referralsSlice.actions;
export default referralsSlice.reducer;
