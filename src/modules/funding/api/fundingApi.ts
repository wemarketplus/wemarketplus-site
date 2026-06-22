import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  CreateFundingRequest,
  FundingRecord,
  ListFundingQuery,
  UpdateFundingRequest,
} from '../types/fundingTypes';

// Grant-CRM funding opportunities — wemarketplus-backend/src/funding.
//   GET /funding, GET /funding/:id, POST /funding, PATCH /funding/:id, DELETE /funding/:id.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const fundingApi = createApi({
  reducerPath: 'fundingApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Funding'],
  endpoints: (build) => ({
    listFunding: build.query<PaginatedPayload<FundingRecord>, ListFundingQuery | void>({
      query: (p) => ({ url: '/funding', params: p ?? undefined }),
      transformResponse: list<FundingRecord>,
      providesTags: ['Funding'],
    }),
    getFunding: build.query<FundingRecord, string>({
      query: (id) => ({ url: `/funding/${id}` }),
      transformResponse: env<FundingRecord>,
      providesTags: ['Funding'],
    }),
    createFunding: build.mutation<FundingRecord, CreateFundingRequest>({
      query: (body) => ({ url: '/funding', method: 'POST', body }),
      transformResponse: env<FundingRecord>,
      invalidatesTags: ['Funding'],
    }),
    updateFunding: build.mutation<FundingRecord, { id: string; patch: UpdateFundingRequest }>({
      query: ({ id, patch }) => ({ url: `/funding/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<FundingRecord>,
      invalidatesTags: ['Funding'],
    }),
    deleteFunding: build.mutation<void, string>({
      query: (id) => ({ url: `/funding/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Funding'],
    }),
  }),
});

export const {
  useListFundingQuery,
  useGetFundingQuery,
  useCreateFundingMutation,
  useUpdateFundingMutation,
  useDeleteFundingMutation,
} = fundingApi;
