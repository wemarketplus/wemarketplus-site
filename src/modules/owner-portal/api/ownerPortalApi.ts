import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type {
  CreatePipelineRecordRequest,
  ListPipelineQuery,
  OwnerCustomer,
  OwnerMetrics,
  PipelineRecord,
  UpdatePipelineRecordRequest,
} from '../types/ownerPortalApiTypes';

// Backend platform owner portal — wemarketplus-backend/src/owner-portal.
//   GET /owner/metrics, GET /owner/customers, POST /owner/customers/:id/suspend,
//   GET/POST/GET:id/PATCH/DELETE /owner/pipeline.
// The owner portal has many fixture-only analytics pages (revenue/churn/usage);
// only metrics + pipeline + customers are backed today.
export const ownerPortalApi = createApi({
  reducerPath: 'ownerPortalApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['OwnerPipeline', 'OwnerCustomer', 'OwnerMetrics'],
  endpoints: (build) => ({
    getOwnerMetrics: build.query<OwnerMetrics, void>({
      query: () => ({ url: '/owner/metrics' }),
      transformResponse: (res: ApiEnvelope<OwnerMetrics>) => res.data,
      providesTags: ['OwnerMetrics'],
    }),
    listOwnerCustomers: build.query<PaginatedPayload<OwnerCustomer>, PaginationParams | void>({
      query: (params) => ({ url: '/owner/customers', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<OwnerCustomer>>) => res.data,
      providesTags: ['OwnerCustomer'],
    }),
    suspendCustomer: build.mutation<OwnerCustomer, string>({
      query: (id) => ({ url: `/owner/customers/${id}/suspend`, method: 'POST' }),
      transformResponse: (res: ApiEnvelope<OwnerCustomer>) => res.data,
      invalidatesTags: ['OwnerCustomer'],
    }),
    listPipeline: build.query<PaginatedPayload<PipelineRecord>, ListPipelineQuery | void>({
      query: (params) => ({ url: '/owner/pipeline', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<PipelineRecord>>) => res.data,
      providesTags: ['OwnerPipeline'],
    }),
    getPipelineRecord: build.query<PipelineRecord, string>({
      query: (id) => ({ url: `/owner/pipeline/${id}` }),
      transformResponse: (res: ApiEnvelope<PipelineRecord>) => res.data,
      providesTags: ['OwnerPipeline'],
    }),
    createPipelineRecord: build.mutation<PipelineRecord, CreatePipelineRecordRequest>({
      query: (body) => ({ url: '/owner/pipeline', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<PipelineRecord>) => res.data,
      invalidatesTags: ['OwnerPipeline', 'OwnerMetrics'],
    }),
    updatePipelineRecord: build.mutation<PipelineRecord, { id: string; patch: UpdatePipelineRecordRequest }>({
      query: ({ id, patch }) => ({ url: `/owner/pipeline/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<PipelineRecord>) => res.data,
      invalidatesTags: ['OwnerPipeline', 'OwnerMetrics'],
    }),
    deletePipelineRecord: build.mutation<void, string>({
      query: (id) => ({ url: `/owner/pipeline/${id}`, method: 'DELETE' }),
      invalidatesTags: ['OwnerPipeline', 'OwnerMetrics'],
    }),
  }),
});

export const {
  useGetOwnerMetricsQuery,
  useListOwnerCustomersQuery,
  useSuspendCustomerMutation,
  useListPipelineQuery,
  useGetPipelineRecordQuery,
  useCreatePipelineRecordMutation,
  useUpdatePipelineRecordMutation,
  useDeletePipelineRecordMutation,
} = ownerPortalApi;
