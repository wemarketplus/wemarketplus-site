import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type {
  ApiEnvelope,
  PaginatedPayload,
  PaginationParams,
} from '@/shared/types';
import type {
  CoverageResponse,
  CreateNurseShiftRequest,
  NurseShiftRecord,
  UpdateNurseShiftRequest,
} from '../types/schedulingTypes';

// Verified against wemarketplus-backend/src/nurse-scheduling/nurse-scheduling.controller.ts:
//   GET    /hl/shifts?page&limit&nurseId&from&to&shiftType&status
//   GET    /hl/shifts/coverage?from&to
//   GET    /hl/shifts/:id
//   POST   /hl/shifts          (admin/owner/manager)
//   PATCH  /hl/shifts/:id      (admin/owner/manager)
//   DELETE /hl/shifts/:id      (admin/owner/manager)
//
// This file was `// TODO(backend): /territories, /smart-scheduling endpoints.` +
// `export {}` — the Gold-gated Smart Scheduling screen had no data layer at all. It is
// now the Nurse Scheduling Engine; the whole controller is behind @RequireFeature
// ('smart_scheduling'), so a tenant below Gold gets 402 and baseQueryWithReauth routes
// them to billing.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export interface ListShiftsQuery extends PaginationParams {
  nurseId?: string;
  from?: string;
  to?: string;
}

export const schedulingApi = createApi({
  reducerPath: 'schedulingApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Shift', 'Coverage'],
  endpoints: (build) => ({
    listShifts: build.query<
      PaginatedPayload<NurseShiftRecord>,
      ListShiftsQuery | void
    >({
      query: (params) => ({ url: '/hl/shifts', params: params ?? undefined }),
      transformResponse: list<NurseShiftRecord>,
      providesTags: ['Shift'],
    }),

    getCoverage: build.query<CoverageResponse, { from?: string; to?: string } | void>({
      query: (params) => ({
        url: '/hl/shifts/coverage',
        params: params ?? undefined,
      }),
      transformResponse: env<CoverageResponse>,
      providesTags: ['Coverage'],
    }),

    createShift: build.mutation<NurseShiftRecord, CreateNurseShiftRequest>({
      query: (body) => ({ url: '/hl/shifts', method: 'POST', body }),
      transformResponse: env<NurseShiftRecord>,
      // A new block changes cover, so both caches are stale.
      invalidatesTags: ['Shift', 'Coverage'],
    }),

    updateShift: build.mutation<
      NurseShiftRecord,
      { id: string; patch: UpdateNurseShiftRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/hl/shifts/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<NurseShiftRecord>,
      invalidatesTags: ['Shift', 'Coverage'],
    }),

    deleteShift: build.mutation<void, string>({
      query: (id) => ({ url: `/hl/shifts/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Shift', 'Coverage'],
    }),
  }),
});

export const {
  useListShiftsQuery,
  useGetCoverageQuery,
  useCreateShiftMutation,
  useUpdateShiftMutation,
  useDeleteShiftMutation,
} = schedulingApi;
