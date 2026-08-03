import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  CompanyDedupPreview,
  CompanyDedupResult,
  CompanyRecord,
  CreateCompanyRequest,
  ListCompaniesQuery,
  UpdateCompanyRequest,
} from '../types/companiesTypes';

// Grant-CRM employer companies — wemarketplus-backend/src/companies.
//   GET/POST/GET:id/PATCH/DELETE  /companies  (+ POST /companies/dedup)
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const companiesApi = createApi({
  reducerPath: 'companiesApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Company'],
  endpoints: (build) => ({
    listCompanies: build.query<PaginatedPayload<CompanyRecord>, ListCompaniesQuery | void>({
      query: (p) => ({ url: '/companies', params: p ?? undefined }),
      transformResponse: list<CompanyRecord>,
      providesTags: ['Company'],
    }),
    getCompany: build.query<CompanyRecord, string>({
      query: (id) => ({ url: `/companies/${id}` }),
      transformResponse: env<CompanyRecord>,
      providesTags: ['Company'],
    }),
    createCompany: build.mutation<CompanyRecord, CreateCompanyRequest>({
      query: (body) => ({ url: '/companies', method: 'POST', body }),
      transformResponse: env<CompanyRecord>,
      invalidatesTags: ['Company'],
    }),
    updateCompany: build.mutation<CompanyRecord, { id: string; patch: UpdateCompanyRequest }>({
      query: ({ id, patch }) => ({ url: `/companies/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<CompanyRecord>,
      invalidatesTags: ['Company'],
    }),
    deleteCompany: build.mutation<void, string>({
      query: (id) => ({ url: `/companies/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Company'],
    }),
    // GET /companies/dedup/preview (admin/owner) — what a dedup run WOULD do.
    // Read-only; used to fill the confirmation dialog before anything is destroyed.
    dedupPreview: build.query<CompanyDedupPreview, void>({
      query: () => ({ url: '/companies/dedup/preview' }),
      transformResponse: env<CompanyDedupPreview>,
      providesTags: ['Company'],
    }),
    // POST /companies/dedup (admin/owner) — merge duplicate employer records.
    dedupCompanies: build.mutation<CompanyDedupResult, void>({
      query: () => ({ url: '/companies/dedup', method: 'POST' }),
      transformResponse: env<CompanyDedupResult>,
      invalidatesTags: ['Company'],
    }),
  }),
});

export const {
  useLazyDedupPreviewQuery,
  useListCompaniesQuery,
  useGetCompanyQuery,
  useCreateCompanyMutation,
  useUpdateCompanyMutation,
  useDeleteCompanyMutation,
  useDedupCompaniesMutation,
} = companiesApi;
