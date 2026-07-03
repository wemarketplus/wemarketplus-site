import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  ContractRecord,
  CreateContractRequest,
  ListContractsQuery,
  UpdateContractRequest,
} from '../types/contractsTypes';

// Grant-CRM contracts — src/contracts. Standard REST. DELETE is Admin/Owner-only
// on the backend (@Roles) — a non-permitted user gets a 403 surfaced by the
// mutation's error toast.
//   GET/POST  /contracts    GET/PATCH/DELETE  /contracts/:id
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const contractsApi = createApi({
  reducerPath: 'contractsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Contract'],
  endpoints: (build) => ({
    listContracts: build.query<PaginatedPayload<ContractRecord>, ListContractsQuery | void>({
      query: (p) => ({ url: '/contracts', params: p ?? undefined }),
      transformResponse: list<ContractRecord>,
      providesTags: ['Contract'],
    }),
    getContract: build.query<ContractRecord, string>({
      query: (id) => ({ url: `/contracts/${id}` }),
      transformResponse: env<ContractRecord>,
      providesTags: ['Contract'],
    }),
    createContract: build.mutation<ContractRecord, CreateContractRequest>({
      query: (body) => ({ url: '/contracts', method: 'POST', body }),
      transformResponse: env<ContractRecord>,
      invalidatesTags: ['Contract'],
    }),
    updateContract: build.mutation<ContractRecord, { id: string; patch: UpdateContractRequest }>({
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
  useListContractsQuery,
  useGetContractQuery,
  useCreateContractMutation,
  useUpdateContractMutation,
  useDeleteContractMutation,
} = contractsApi;
