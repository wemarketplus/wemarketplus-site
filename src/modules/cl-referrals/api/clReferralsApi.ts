import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  ClPaidReferralRecord,
  ClReferralSourceRecord,
  CreateClPaidReferralRequest,
  CreateClReferralSourceRequest,
} from '../types/clReferralsApiTypes';

// CommunityLink referrals — wemarketplus-backend cl/referral-sources, cl/paid-referrals.
//   GET/POST/GET:id/PATCH/DELETE  /cl/referral-sources
//   GET/POST/GET:id/PATCH/DELETE  /cl/paid-referrals
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const clReferralsApi = createApi({
  reducerPath: 'clReferralsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClRefSource', 'ClPaidReferral'],
  endpoints: (build) => ({
    listClReferralSources: build.query<PaginatedPayload<ClReferralSourceRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/referral-sources', params: p ?? undefined }),
      transformResponse: list<ClReferralSourceRecord>,
      providesTags: ['ClRefSource'],
    }),
    createClReferralSource: build.mutation<ClReferralSourceRecord, CreateClReferralSourceRequest>({
      query: (body) => ({ url: '/cl/referral-sources', method: 'POST', body }),
      transformResponse: env<ClReferralSourceRecord>,
      invalidatesTags: ['ClRefSource'],
    }),
    updateClReferralSource: build.mutation<ClReferralSourceRecord, { id: string; patch: Partial<CreateClReferralSourceRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/referral-sources/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClReferralSourceRecord>,
      invalidatesTags: ['ClRefSource'],
    }),
    deleteClReferralSource: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/referral-sources/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClRefSource'],
    }),
    listClPaidReferrals: build.query<PaginatedPayload<ClPaidReferralRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/paid-referrals', params: p ?? undefined }),
      transformResponse: list<ClPaidReferralRecord>,
      providesTags: ['ClPaidReferral'],
    }),
    createClPaidReferral: build.mutation<ClPaidReferralRecord, CreateClPaidReferralRequest>({
      query: (body) => ({ url: '/cl/paid-referrals', method: 'POST', body }),
      transformResponse: env<ClPaidReferralRecord>,
      invalidatesTags: ['ClPaidReferral'],
    }),
    updateClPaidReferral: build.mutation<ClPaidReferralRecord, { id: string; patch: Partial<CreateClPaidReferralRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/paid-referrals/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClPaidReferralRecord>,
      invalidatesTags: ['ClPaidReferral'],
    }),
    deleteClPaidReferral: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/paid-referrals/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClPaidReferral'],
    }),
  }),
});

export const {
  useListClReferralSourcesQuery,
  useCreateClReferralSourceMutation,
  useUpdateClReferralSourceMutation,
  useDeleteClReferralSourceMutation,
  useListClPaidReferralsQuery,
  useCreateClPaidReferralMutation,
  useUpdateClPaidReferralMutation,
  useDeleteClPaidReferralMutation,
} = clReferralsApi;
