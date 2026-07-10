import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  ClCompetitorRecord,
  ClConcessionRecord,
  ClLocPricingRecord,
  ClRevenueEntryRecord,
  CreateClCompetitorRequest,
  CreateClConcessionRequest,
  CreateClLocPricingRequest,
  CreateClRevenueEntryRequest,
} from '../types/clFinancialApiTypes';

// CommunityLink financial command centre — wemarketplus-backend cl/* resources.
//   /cl/revenue-entries  /cl/concessions  /cl/competitors  /cl/loc-pricing
// All uniform CRUD under /api.

const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const clFinancialApi = createApi({
  reducerPath: 'clFinancialApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClRevenue', 'ClConcession', 'ClCompetitor', 'ClLocPricing'],
  endpoints: (build) => ({
    // revenue entries
    listClRevenue: build.query<PaginatedPayload<ClRevenueEntryRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/revenue-entries', params: p ?? undefined }),
      transformResponse: list<ClRevenueEntryRecord>,
      providesTags: ['ClRevenue'],
    }),
    createClRevenue: build.mutation<ClRevenueEntryRecord, CreateClRevenueEntryRequest>({
      query: (body) => ({ url: '/cl/revenue-entries', method: 'POST', body }),
      transformResponse: env<ClRevenueEntryRecord>,
      invalidatesTags: ['ClRevenue'],
    }),
    updateClRevenue: build.mutation<ClRevenueEntryRecord, { id: string; patch: Partial<CreateClRevenueEntryRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/revenue-entries/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClRevenueEntryRecord>,
      invalidatesTags: ['ClRevenue'],
    }),
    deleteClRevenue: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/revenue-entries/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClRevenue'],
    }),
    // concessions
    listClConcessions: build.query<PaginatedPayload<ClConcessionRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/concessions', params: p ?? undefined }),
      transformResponse: list<ClConcessionRecord>,
      providesTags: ['ClConcession'],
    }),
    createClConcession: build.mutation<ClConcessionRecord, CreateClConcessionRequest>({
      query: (body) => ({ url: '/cl/concessions', method: 'POST', body }),
      transformResponse: env<ClConcessionRecord>,
      invalidatesTags: ['ClConcession'],
    }),
    updateClConcession: build.mutation<ClConcessionRecord, { id: string; patch: Partial<CreateClConcessionRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/concessions/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClConcessionRecord>,
      invalidatesTags: ['ClConcession'],
    }),
    deleteClConcession: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/concessions/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClConcession'],
    }),
    // competitors
    listClCompetitors: build.query<PaginatedPayload<ClCompetitorRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/competitors', params: p ?? undefined }),
      transformResponse: list<ClCompetitorRecord>,
      providesTags: ['ClCompetitor'],
    }),
    createClCompetitor: build.mutation<ClCompetitorRecord, CreateClCompetitorRequest>({
      query: (body) => ({ url: '/cl/competitors', method: 'POST', body }),
      transformResponse: env<ClCompetitorRecord>,
      invalidatesTags: ['ClCompetitor'],
    }),
    deleteClCompetitor: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/competitors/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClCompetitor'],
    }),
    // level-of-care pricing
    listClLocPricing: build.query<PaginatedPayload<ClLocPricingRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/loc-pricing', params: p ?? undefined }),
      transformResponse: list<ClLocPricingRecord>,
      providesTags: ['ClLocPricing'],
    }),
    createClLocPricing: build.mutation<ClLocPricingRecord, CreateClLocPricingRequest>({
      query: (body) => ({ url: '/cl/loc-pricing', method: 'POST', body }),
      transformResponse: env<ClLocPricingRecord>,
      invalidatesTags: ['ClLocPricing'],
    }),
    deleteClLocPricing: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/loc-pricing/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClLocPricing'],
    }),
  }),
});

export const {
  useListClRevenueQuery,
  useCreateClRevenueMutation,
  useUpdateClRevenueMutation,
  useDeleteClRevenueMutation,
  useListClConcessionsQuery,
  useCreateClConcessionMutation,
  useUpdateClConcessionMutation,
  useDeleteClConcessionMutation,
  useListClCompetitorsQuery,
  useCreateClCompetitorMutation,
  useDeleteClCompetitorMutation,
  useListClLocPricingQuery,
  useCreateClLocPricingMutation,
  useDeleteClLocPricingMutation,
} = clFinancialApi;
