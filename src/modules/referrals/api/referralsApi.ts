import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { REFERRALS_TAGS } from '../constants/referralsConstants';
import type {
  CreateReferralSourceRequest,
  ListReferralSourcesQuery,
  ReferralSourceRecord,
  UpdateReferralSourceRequest,
} from '../types/referralsTypes';

// Verified against wemarketplus-backend/src/referral-sources/referral-sources.controller.ts.
// NOTE: backend route prefix is /referral-sources (not /referrals).
//   GET    /referral-sources?page&limit -> PaginatedResult<ReferralSourceResponseDto>
//   GET    /referral-sources/:id
//   POST   /referral-sources            body:CreateReferralSourceDto
//   PATCH  /referral-sources/:id        body:UpdateReferralSourceDto
//   DELETE /referral-sources/:id
export const referralsApi = createApi({
  reducerPath: 'referralsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [REFERRALS_TAGS.List, REFERRALS_TAGS.Detail],
  endpoints: (build) => ({
    listReferrals: build.query<PaginatedPayload<ReferralSourceRecord>, ListReferralSourcesQuery | void>({
      query: (params) => ({ url: '/referral-sources', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ReferralSourceRecord>>) => res.data,
      providesTags: (result) =>
        result
          ? [
              ...result.data.map((r) => ({ type: REFERRALS_TAGS.Detail, id: r.id }) as const),
              { type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' },
            ]
          : [{ type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    getReferral: build.query<ReferralSourceRecord, string>({
      query: (id) => ({ url: `/referral-sources/${id}` }),
      transformResponse: (res: ApiEnvelope<ReferralSourceRecord>) => res.data,
      providesTags: (_r, _e, id) => [{ type: REFERRALS_TAGS.Detail, id }],
    }),
    createReferral: build.mutation<ReferralSourceRecord, CreateReferralSourceRequest>({
      query: (body) => ({ url: '/referral-sources', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<ReferralSourceRecord>) => res.data,
      invalidatesTags: [{ type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    updateReferral: build.mutation<ReferralSourceRecord, { id: string; patch: UpdateReferralSourceRequest }>({
      query: ({ id, patch }) => ({ url: `/referral-sources/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ReferralSourceRecord>) => res.data,
      invalidatesTags: (_r, _e, { id }) => [
        { type: REFERRALS_TAGS.Detail, id },
        { type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    deleteReferral: build.mutation<void, string>({
      query: (id) => ({ url: `/referral-sources/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: REFERRALS_TAGS.Detail, id },
        { type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
  }),
});

export const {
  useListReferralsQuery,
  useGetReferralQuery,
  useCreateReferralMutation,
  useUpdateReferralMutation,
  useDeleteReferralMutation,
} = referralsApi;
