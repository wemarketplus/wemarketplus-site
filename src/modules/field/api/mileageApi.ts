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
  MileageSummary,
  TeamMileageSummary,
  ExpenseReceiptRecord,
  CreateExpenseReceiptRequest,
  UploadExpenseReceiptRequest,
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
  tagTypes: ['MileageLog', 'ExpenseReceipt'],
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

    /**
     * Week/month totals, aggregated SERVER-side over every trip. The page's own
     * rows are the most recent N, so summing them would under-report a busy
     * rep's reimbursement — a number that is quietly too low is worse than none.
     */
    getMileageSummary: build.query<MileageSummary, void>({
      query: () => ({ url: '/mileage-logs/summary' }),
      transformResponse: (res: ApiEnvelope<MileageSummary>) => res.data,
      providesTags: ['MileageLog'],
    }),

    /**
     * TEAM-wide mileage for the Admin / Office Manager team page.
     *
     * A separate endpoint rather than a `userId` parameter on the summary above:
     * the personal route deliberately exposes no way to total someone else's
     * reimbursement, so the team view is its own Admin/Owner-gated route. Called
     * only from behind a RoleGate for that reason.
     */
    getTeamMileageSummary: build.query<TeamMileageSummary, void>({
      query: () => ({ url: '/mileage-logs/team-summary' }),
      transformResponse: env<TeamMileageSummary>,
      providesTags: ['MileageLog'],
    }),
    // Expense receipts — /expense-receipts had a complete backend (create, list,
    // review, delete) and NO client at all, so "attach receipt images" was
    // unreachable despite being sold at Max.
    listExpenseReceipts: build.query<
      PaginatedPayload<ExpenseReceiptRecord>,
      { limit?: number } | void
    >({
      query: (params) => ({ url: '/expense-receipts', params: params ?? undefined }),
      transformResponse: list<ExpenseReceiptRecord>,
      providesTags: ['ExpenseReceipt'],
    }),
    createExpenseReceipt: build.mutation<
      ExpenseReceiptRecord,
      CreateExpenseReceiptRequest
    >({
      query: (body) => ({ url: '/expense-receipts', method: 'POST', body }),
      transformResponse: env<ExpenseReceiptRecord>,
      invalidatesTags: ['ExpenseReceipt'],
    }),

    /**
     * Attach a photo of the receipt — a REAL multipart upload to the server,
     * not a link to a file the worker parked in their own Drive.
     *
     * Deliberately NO `Content-Type` header. `fetchBaseQuery` passes a FormData
     * body straight to `fetch`, which sets `multipart/form-data` together with
     * the boundary it generated; setting the header by hand omits the boundary
     * and the server cannot parse a single field.
     *
     * `undefined` fields are skipped rather than appended: FormData stringifies
     * everything, so an absent `mileageLogId` would arrive as the literal
     * "undefined" and fail the server's @IsUUID.
     */
    uploadExpenseReceipt: build.mutation<
      ExpenseReceiptRecord,
      UploadExpenseReceiptRequest
    >({
      query: ({ file, ...fields }) => {
        const body = new FormData();
        body.append('file', file);
        Object.entries(fields).forEach(([key, value]) => {
          if (value !== undefined) body.append(key, String(value));
        });
        return { url: '/expense-receipts/upload', method: 'POST', body };
      },
      transformResponse: env<ExpenseReceiptRecord>,
      invalidatesTags: ['ExpenseReceipt'],
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
  useGetMileageSummaryQuery,
  useGetTeamMileageSummaryQuery,
  useListExpenseReceiptsQuery,
  useCreateExpenseReceiptMutation,
  useUploadExpenseReceiptMutation,
  useCreateMileageLogMutation,
  useUpdateMileageLogMutation,
  useDeleteMileageLogMutation,
} = mileageApi;
