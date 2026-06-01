import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type {
  ApiEnvelope,
  PaginatedPayload,
  ReferralSource,
} from '@/shared/types';
import { REFERRALS_TAGS } from '../constants/referralsConstants';

// TODO(backend): /referrals CRUD endpoints. Until then, useReferralsList
// falls back to REFERRAL_SOURCES_FIXTURE.
export const referralsApi = createApi({
  reducerPath: 'referralsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [REFERRALS_TAGS.List, REFERRALS_TAGS.Detail],
  endpoints: (build) => ({
    listReferrals: build.query<
      PaginatedPayload<ReferralSource>,
      { page?: number; limit?: number }
    >({
      query: (params = {}) => ({ url: '/referrals', params }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ReferralSource>>) =>
        res.data,
      providesTags: [{ type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
  }),
});

export const { useListReferralsQuery } = referralsApi;
