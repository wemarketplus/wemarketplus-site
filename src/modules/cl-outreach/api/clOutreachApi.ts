import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import { cleanListParams } from '@/shared/utils/queryParams';
import type {
  ClOutreachVisitRecord,
  ClTaskRecord,
  CreateClOutreachVisitRequest,
  CreateClTaskRequest,
} from '../types/clOutreachApiTypes';

// Server-side list params: pagination + search + type filter (ClListQueryDto).
export interface ClVisitListParams extends PaginationParams {
  search?: string;
  type?: string;
}

// CommunityLink outreach — wemarketplus-backend cl/outreach-visits, cl/tasks.
//   GET/POST/GET:id/PATCH/DELETE  /cl/outreach-visits
//   GET/POST/GET:id/PATCH/DELETE  /cl/tasks
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const clOutreachApi = createApi({
  reducerPath: 'clOutreachApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClVisit', 'ClTask'],
  endpoints: (build) => ({
    listClVisits: build.query<PaginatedPayload<ClOutreachVisitRecord>, ClVisitListParams | void>({
      query: (p) => ({ url: '/cl/outreach-visits', params: cleanListParams(p ?? undefined) }),
      transformResponse: list<ClOutreachVisitRecord>,
      providesTags: ['ClVisit'],
    }),
    createClVisit: build.mutation<ClOutreachVisitRecord, CreateClOutreachVisitRequest>({
      query: (body) => ({ url: '/cl/outreach-visits', method: 'POST', body }),
      transformResponse: env<ClOutreachVisitRecord>,
      invalidatesTags: ['ClVisit'],
    }),
    updateClVisit: build.mutation<ClOutreachVisitRecord, { id: string; patch: Partial<CreateClOutreachVisitRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/outreach-visits/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClOutreachVisitRecord>,
      invalidatesTags: ['ClVisit'],
    }),
    deleteClVisit: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/outreach-visits/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClVisit'],
    }),
    listClTasks: build.query<PaginatedPayload<ClTaskRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/cl/tasks', params: p ?? undefined }),
      transformResponse: list<ClTaskRecord>,
      providesTags: ['ClTask'],
    }),
    createClTask: build.mutation<ClTaskRecord, CreateClTaskRequest>({
      query: (body) => ({ url: '/cl/tasks', method: 'POST', body }),
      transformResponse: env<ClTaskRecord>,
      invalidatesTags: ['ClTask'],
    }),
    updateClTask: build.mutation<ClTaskRecord, { id: string; patch: Partial<CreateClTaskRequest> }>({
      query: ({ id, patch }) => ({ url: `/cl/tasks/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ClTaskRecord>,
      invalidatesTags: ['ClTask'],
    }),
    deleteClTask: build.mutation<void, string>({
      query: (id) => ({ url: `/cl/tasks/${id}`, method: 'DELETE' }),
      invalidatesTags: ['ClTask'],
    }),
  }),
});

export const {
  useListClVisitsQuery,
  useCreateClVisitMutation,
  useUpdateClVisitMutation,
  useDeleteClVisitMutation,
  useListClTasksQuery,
  useCreateClTaskMutation,
  useUpdateClTaskMutation,
  useDeleteClTaskMutation,
} = clOutreachApi;
