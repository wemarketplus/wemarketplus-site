import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import { cleanListParams } from '@/shared/utils/queryParams';
import type {
  ClTourRecord,
  CreateClTourRequest,
  UpdateClTourRequest,
} from '../types/clToursApiTypes';

// Server-side list params: pagination + search + status filter (ClListQueryDto).
export interface ClTourListParams extends PaginationParams {
  search?: string;
  status?: string;
}

// CommunityLink tours — wemarketplus-backend cl/tours (uniform CRUD).
//   GET/POST/GET:id/PATCH/DELETE /cl/tours
export const clToursApi = createApi({
  reducerPath: 'clToursApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClTour'],
  endpoints: (build) => ({
    listClTours: build.query<PaginatedPayload<ClTourRecord>, ClTourListParams | void>({
      query: (params) => ({ url: '/cl/tours', params: cleanListParams(params ?? undefined) }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<ClTourRecord>>) => res.data,
      providesTags: ['ClTour'],
    }),
    createClTour: build.mutation<ClTourRecord, CreateClTourRequest>({
      query: (body) => ({ url: '/cl/tours', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<ClTourRecord>) => res.data,
      invalidatesTags: ['ClTour'],
    }),
    updateClTour: build.mutation<ClTourRecord, { id: string; patch: UpdateClTourRequest }>({
      query: ({ id, patch }) => ({ url: `/cl/tours/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<ClTourRecord>) => res.data,
      invalidatesTags: ['ClTour'],
    }),
    deleteClTour: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/tours/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClTour'],
    }),
  }),
});

export const {
  useListClToursQuery,
  useCreateClTourMutation,
  useUpdateClTourMutation,
  useDeleteClTourMutation,
} = clToursApi;
