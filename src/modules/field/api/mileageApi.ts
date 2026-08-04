import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type {
  ApiEnvelope,
  PaginatedPayload,
  PaginationParams,
} from '@/shared/types';
import type {
  CreateMileageLogRequest,
  MileageLogRecord,
  UpdateMileageLogRequest,
} from '../types/fieldTypes';

// Verified against wemarketplus-backend/src/mileage/mileage.controller.ts:
//   GET    /mileage-logs?page&limit
//   GET    /mileage-logs/:id
//   POST   /mileage-logs
//   PATCH  /mileage-logs/:id
//   DELETE /mileage-logs/:id
//
// The mileage tables and endpoints have existed the whole time with NO client at
// all — this file is the first one. EVV had the opposite problem: written RTK hooks
// (clinicalApi) consumed by zero components. Both are sold at Max as "EVV/GPS
// mileage & compliance log".
//
// NOTE the route is NOT product-gated on the server (`/mileage-logs` carries no
// @RequireProduct), because CommunityLink sells a mileage surface too. The nav entry
// and route are HospiceLink-scoped on this side; do not read the missing decorator
// as an oversight.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const mileageApi = createApi({
  reducerPath: 'mileageApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['MileageLog'],
  endpoints: (build) => ({
    listMileageLogs: build.query<
      PaginatedPayload<MileageLogRecord>,
      PaginationParams | void
    >({
      query: (params) => ({
        url: '/mileage-logs',
        params: params ?? undefined,
      }),
      transformResponse: list<MileageLogRecord>,
      providesTags: ['MileageLog'],
    }),

    createMileageLog: build.mutation<MileageLogRecord, CreateMileageLogRequest>({
      query: (body) => ({ url: '/mileage-logs', method: 'POST', body }),
      transformResponse: env<MileageLogRecord>,
      invalidatesTags: ['MileageLog'],
    }),

    updateMileageLog: build.mutation<
      MileageLogRecord,
      { id: string; patch: UpdateMileageLogRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/mileage-logs/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<MileageLogRecord>,
      invalidatesTags: ['MileageLog'],
    }),

    deleteMileageLog: build.mutation<void, string>({
      query: (id) => ({ url: `/mileage-logs/${id}`, method: 'DELETE' }),
      invalidatesTags: ['MileageLog'],
    }),
  }),
});

export const {
  useListMileageLogsQuery,
  useCreateMileageLogMutation,
  useUpdateMileageLogMutation,
  useDeleteMileageLogMutation,
} = mileageApi;
