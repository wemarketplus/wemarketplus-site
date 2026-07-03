import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type { AgreementStatus } from '../constants/agreementsConstants';
import type {
  AgreementRecord,
  AgreementStats,
  ContractRecord,
  CreateAgreementRequest,
  CreateContractRequest,
} from '../types/agreementsTypes';

// Grant-CRM agreements + contracts — wemarketplus-backend/src/agreements, contracts.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const agreementsApi = createApi({
  reducerPath: 'agreementsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Agreement', 'Contract'],
  endpoints: (build) => ({
    listAgreements: build.query<PaginatedPayload<AgreementRecord>, (PaginationParams & { status?: AgreementStatus }) | void>({
      query: (p) => ({ url: '/agreements', params: p ?? undefined }),
      transformResponse: list<AgreementRecord>,
      providesTags: ['Agreement'],
    }),
    getAgreementStats: build.query<AgreementStats, void>({
      query: () => ({ url: '/agreements/stats' }),
      transformResponse: env<AgreementStats>,
      providesTags: ['Agreement'],
    }),
    createAgreement: build.mutation<AgreementRecord, CreateAgreementRequest>({
      query: (body) => ({ url: '/agreements', method: 'POST', body }),
      transformResponse: env<AgreementRecord>,
      invalidatesTags: ['Agreement'],
    }),
    updateAgreement: build.mutation<AgreementRecord, { id: string; patch: Partial<CreateAgreementRequest> }>({
      query: ({ id, patch }) => ({ url: `/agreements/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<AgreementRecord>,
      invalidatesTags: ['Agreement'],
    }),
    deleteAgreement: build.mutation<void, string>({
      query: (id) => ({ url: `/agreements/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Agreement'],
    }),
    listContracts: build.query<PaginatedPayload<ContractRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/contracts', params: p ?? undefined }),
      transformResponse: list<ContractRecord>,
      providesTags: ['Contract'],
    }),
    createContract: build.mutation<ContractRecord, CreateContractRequest>({
      query: (body) => ({ url: '/contracts', method: 'POST', body }),
      transformResponse: env<ContractRecord>,
      invalidatesTags: ['Contract'],
    }),
    updateContract: build.mutation<ContractRecord, { id: string; patch: Partial<CreateContractRequest> }>({
      query: ({ id, patch }) => ({ url: `/contracts/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ContractRecord>,
      invalidatesTags: ['Contract'],
    }),
    deleteContract: build.mutation<void, string>({
      query: (id) => ({ url: `/contracts/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Contract'],
    }),
  }),
});

export const {
  useListAgreementsQuery,
  useGetAgreementStatsQuery,
  useCreateAgreementMutation,
  useUpdateAgreementMutation,
  useDeleteAgreementMutation,
  useListContractsQuery,
  useCreateContractMutation,
  useUpdateContractMutation,
  useDeleteContractMutation,
} = agreementsApi;
