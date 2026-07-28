import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { JOBS_TAGS } from '../constants/jobsConstants';
import type {
  CreateJobRequest,
  JobRecord,
  ListJobsQuery,
  UpdateJobRequest,
} from '../types/jobsTypes';

// Verified against wemarketplus-backend/src/jobs/jobs.controller.ts:
//   GET    /hl/jobs?page&limit&pipelineId&companyId&contactId&assignedTo&jobType&status&priority
//   GET    /hl/jobs/:id
//   POST   /hl/jobs
//   PATCH  /hl/jobs/:id
//   DELETE /hl/jobs/:id   (admin/owner/manager only)
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const jobsApi = createApi({
  reducerPath: 'jobsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [JOBS_TAGS.List, JOBS_TAGS.Detail],
  endpoints: (build) => ({
    listJobs: build.query<PaginatedPayload<JobRecord>, ListJobsQuery | void>({
      query: (params) => ({ url: '/hl/jobs', params: params ?? undefined }),
      transformResponse: list<JobRecord>,
      providesTags: (result) =>
        result
          ? [
              ...result.data.map(
                (j) => ({ type: JOBS_TAGS.Detail, id: j.id }) as const,
              ),
              { type: JOBS_TAGS.List, id: 'PARTIAL-LIST' },
            ]
          : [{ type: JOBS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    getJob: build.query<JobRecord, string>({
      query: (id) => ({ url: `/hl/jobs/${id}` }),
      transformResponse: env<JobRecord>,
      providesTags: (_r, _e, id) => [{ type: JOBS_TAGS.Detail, id }],
    }),
    createJob: build.mutation<JobRecord, CreateJobRequest>({
      query: (body) => ({ url: '/hl/jobs', method: 'POST', body }),
      transformResponse: env<JobRecord>,
      invalidatesTags: [{ type: JOBS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    updateJob: build.mutation<JobRecord, { id: string; patch: UpdateJobRequest }>({
      query: ({ id, patch }) => ({
        url: `/hl/jobs/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<JobRecord>,
      invalidatesTags: (_r, _e, { id }) => [
        { type: JOBS_TAGS.Detail, id },
        { type: JOBS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    deleteJob: build.mutation<void, string>({
      query: (id) => ({ url: `/hl/jobs/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: JOBS_TAGS.Detail, id },
        { type: JOBS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
  }),
});

export const {
  useListJobsQuery,
  useGetJobQuery,
  useCreateJobMutation,
  useUpdateJobMutation,
  useDeleteJobMutation,
} = jobsApi;
