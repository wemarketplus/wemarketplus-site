import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import { cleanListParams } from '@/shared/utils/queryParams';
import type {
  ClCompetitorRecord,
  ClConcessionRecord,
  ClLeakageItemRecord,
  ClLocPricingRecord,
  ClRevenueEntryRecord,
  CreateClCompetitorRequest,
  CreateClConcessionRequest,
  CreateClLeakageItemRequest,
  CreateClLocPricingRequest,
  CreateClRevenueEntryRequest,
} from '../types/clFinancialApiTypes';

// CommunityLink financial command centre — wemarketplus-backend cl/* resources.
//   /cl/revenue-entries  /cl/concessions  /cl/competitors  /cl/loc-pricing  /cl/leakage-items
// All uniform CRUD under /api.

const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

// Server-side list params: pagination + search (+ status for concessions/leakage).
export interface FinRevenueListParams extends PaginationParams { search?: string; }
export interface FinConcessionListParams extends PaginationParams { search?: string; status?: string; }
export interface FinCompetitorListParams extends PaginationParams { search?: string; }
export interface FinLeakageListParams extends PaginationParams { search?: string; status?: string; }

export const clFinancialApi = createApi({
  reducerPath: 'clFinancialApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClRevenue', 'ClConcession', 'ClCompetitor', 'ClLocPricing', 'ClLeakageItem'],
  endpoints: (build) => ({
    // revenue entries
    listClRevenue: build.query<PaginatedPayload<ClRevenueEntryRecord>, FinRevenueListParams | void>({
      query: (p) => ({ url: '/cl/revenue-entries', params: cleanListParams(p ?? undefined) }),
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
    listClConcessions: build.query<PaginatedPayload<ClConcessionRecord>, FinConcessionListParams | void>({
      query: (p) => ({ url: '/cl/concessions', params: cleanListParams(p ?? undefined) }),
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
    listClCompetitors: build.query<PaginatedPayload<ClCompetitorRecord>, FinCompetitorListParams | void>({
      query: (p) => ({ url: '/cl/competitors', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClCompetitorRecord>,
      providesTags: ['ClCompetitor'],
    }),
    createClCompetitor: build.mutation<ClCompetitorRecord, CreateClCompetitorRequest>({
      query: (body) => ({ url: '/cl/competitors', method: 'POST', body }),
      transformResponse: env<ClCompetitorRecord>,
      invalidatesTags: ['ClCompetitor'],
    }),
    updateClCompetitor: build.mutation<ClCompetitorRecord, { id: string; patch: Partial<CreateClCompetitorRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/competitors/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClCompetitorRecord>,
      invalidatesTags: ['ClCompetitor'],
    }),
    deleteClCompetitor: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/competitors/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClCompetitor'],
    }),
    // level-of-care pricing
    listClLocPricing: build.query<PaginatedPayload<ClLocPricingRecord>, FinCompetitorListParams | void>({
      query: (p) => ({ url: '/cl/loc-pricing', params: p ?? undefined }),
      transformResponse: list<ClLocPricingRecord>,
      providesTags: ['ClLocPricing'],
    }),
    createClLocPricing: build.mutation<ClLocPricingRecord, CreateClLocPricingRequest>({
      query: (body) => ({ url: '/cl/loc-pricing', method: 'POST', body }),
      transformResponse: env<ClLocPricingRecord>,
      invalidatesTags: ['ClLocPricing'],
    }),
    updateClLocPricing: build.mutation<ClLocPricingRecord, { id: string; patch: Partial<CreateClLocPricingRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/loc-pricing/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClLocPricingRecord>,
      invalidatesTags: ['ClLocPricing'],
    }),
    deleteClLocPricing: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/loc-pricing/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClLocPricing'],
    }),
    // revenue leakage items
    listClLeakageItems: build.query<PaginatedPayload<ClLeakageItemRecord>, FinLeakageListParams | void>({
      query: (p) => ({ url: '/cl/leakage-items', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClLeakageItemRecord>,
      providesTags: ['ClLeakageItem'],
    }),
    createClLeakageItem: build.mutation<ClLeakageItemRecord, CreateClLeakageItemRequest>({
      query: (body) => ({ url: '/cl/leakage-items', method: 'POST', body }),
      transformResponse: env<ClLeakageItemRecord>,
      invalidatesTags: ['ClLeakageItem'],
    }),
    updateClLeakageItem: build.mutation<ClLeakageItemRecord, { id: string; patch: Partial<CreateClLeakageItemRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/leakage-items/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClLeakageItemRecord>,
      invalidatesTags: ['ClLeakageItem'],
    }),
    deleteClLeakageItem: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/leakage-items/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClLeakageItem'],
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
  useUpdateClCompetitorMutation,
  useDeleteClCompetitorMutation,
  useListClLocPricingQuery,
  useCreateClLocPricingMutation,
  useUpdateClLocPricingMutation,
  useDeleteClLocPricingMutation,
  useListClLeakageItemsQuery,
  useCreateClLeakageItemMutation,
  useUpdateClLeakageItemMutation,
  useDeleteClLeakageItemMutation,
} = clFinancialApi;
