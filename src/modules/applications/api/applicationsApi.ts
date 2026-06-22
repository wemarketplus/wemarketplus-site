import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import type {
  ApplicationRecord,
  CreateApplicationRequest,
  ListApplicationsQuery,
  UpdateApplicationRequest,
} from '../types/applicationsTypes';

// Grant-CRM applications — wemarketplus-backend/src/applications.
//   GET /applications, GET /applications/:id, POST /applications,
//   PATCH /applications/:id, DELETE /applications/:id.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const applicationsApi = createApi({
  reducerPath: 'applicationsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Application'],
  endpoints: (build) => ({
    listApplications: build.query<PaginatedPayload<ApplicationRecord>, ListApplicationsQuery | void>({
      query: (p) => ({ url: '/applications', params: p ?? undefined }),
      transformResponse: list<ApplicationRecord>,
      providesTags: ['Application'],
    }),
    getApplication: build.query<ApplicationRecord, string>({
      query: (id) => ({ url: `/applications/${id}` }),
      transformResponse: env<ApplicationRecord>,
      providesTags: ['Application'],
    }),
    createApplication: build.mutation<ApplicationRecord, CreateApplicationRequest>({
      query: (body) => ({ url: '/applications', method: 'POST', body }),
      transformResponse: env<ApplicationRecord>,
      invalidatesTags: ['Application'],
    }),
    updateApplication: build.mutation<ApplicationRecord, { id: string; patch: UpdateApplicationRequest }>({
      query: ({ id, patch }) => ({ url: `/applications/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<ApplicationRecord>,
      invalidatesTags: ['Application'],
    }),
    deleteApplication: build.mutation<void, string>({
      query: (id) => ({ url: `/applications/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Application'],
    }),
  }),
});

export const {
  useListApplicationsQuery,
  useGetApplicationQuery,
  useCreateApplicationMutation,
  useUpdateApplicationMutation,
  useDeleteApplicationMutation,
} = applicationsApi;
