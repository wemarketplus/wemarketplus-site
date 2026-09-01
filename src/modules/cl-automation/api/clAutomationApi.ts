import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import { cleanListParams } from '@/shared/utils/queryParams';
import type {
  CreateSequenceRequest,
  EnrollmentRecord,
  SequenceRecord,
  UpdateSequenceRequest,
} from '../types/clAutomationTypes';

// Verified against wemarketplus-backend/src/automation-sequences/
// automation-sequences.controller.ts:
//   POST   /automation/sequences              body:CreateSequenceDto   (Admin/Owner/Manager)
//   GET    /automation/sequences              paginated
//   GET    /automation/sequences/enrollments  paginated, ?sequenceId
//   GET    /automation/sequences/:id          + steps + activeEnrollments
//   PATCH  /automation/sequences/:id          body:UpdateSequenceDto   (Admin/Owner/Manager)
//   DELETE /automation/sequences/:id          204                       (Admin/Owner/Manager)
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export interface EnrollmentListParams extends PaginationParams {
  sequenceId?: string;
}

export const clAutomationApi = createApi({
  reducerPath: 'clAutomationApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Sequence', 'Enrollment'],
  endpoints: (build) => ({
    listSequences: build.query<
      PaginatedPayload<SequenceRecord>,
      PaginationParams | void
    >({
      query: (p) => ({
        url: '/automation/sequences',
        params: cleanListParams(p ?? undefined),
      }),
      transformResponse: list<SequenceRecord>,
      providesTags: ['Sequence'],
    }),
    getSequence: build.query<SequenceRecord, string>({
      query: (id) => ({ url: `/automation/sequences/${id}` }),
      transformResponse: env<SequenceRecord>,
      providesTags: ['Sequence'],
    }),
    createSequence: build.mutation<SequenceRecord, CreateSequenceRequest>({
      query: (body) => ({ url: '/automation/sequences', method: 'POST', body }),
      transformResponse: env<SequenceRecord>,
      // Enrollment too: switching a sequence off cancels runs, so a stale runs
      // list would show campaigns as still going after they were stopped.
      invalidatesTags: ['Sequence', 'Enrollment'],
    }),
    updateSequence: build.mutation<
      SequenceRecord,
      { id: string; patch: UpdateSequenceRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/automation/sequences/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<SequenceRecord>,
      invalidatesTags: ['Sequence', 'Enrollment'],
    }),
    deleteSequence: build.mutation<void, string>({
      query: (id) => ({ url: `/automation/sequences/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Sequence', 'Enrollment'],
    }),
    listEnrollments: build.query<
      PaginatedPayload<EnrollmentRecord>,
      EnrollmentListParams | void
    >({
      query: (p) => ({
        url: '/automation/sequences/enrollments',
        params: cleanListParams(p ?? undefined),
      }),
      transformResponse: list<EnrollmentRecord>,
      providesTags: ['Enrollment'],
    }),
  }),
});

export const {
  useListSequencesQuery,
  useGetSequenceQuery,
  useCreateSequenceMutation,
  useUpdateSequenceMutation,
  useDeleteSequenceMutation,
  useListEnrollmentsQuery,
} = clAutomationApi;
