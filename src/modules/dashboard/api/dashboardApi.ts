import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { DashboardSummary, MyDay } from '../types/dashboardTypes';

// Backend dashboard — wemarketplus-backend/src/dashboard.
//   GET /dashboard/summary -> DashboardSummaryDto (tenant-scoped KPI aggregate:
//   prospects by stage, open tasks, overdue/outstanding invoices, unread
//   notifications, recent activity). Recent activity is folded into the summary.
export const dashboardApi = createApi({
  reducerPath: 'dashboardApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['DashboardSummary'],
  endpoints: (build) => ({
    /**
     * The marketer's own morning view. Separate from `summary`, which is the
     * tenant-wide roll-up — this one is always scoped to the caller and carries
     * no figures a field user cannot act on.
     */
    getMyDay: build.query<MyDay, void>({
      query: () => ({ url: '/dashboard/my-day' }),
      transformResponse: (res: ApiEnvelope<MyDay>) => res.data,
    }),
    getDashboardSummary: build.query<DashboardSummary, void>({
      query: () => ({ url: '/dashboard/summary' }),
      transformResponse: (res: ApiEnvelope<DashboardSummary>) => res.data,
      providesTags: ['DashboardSummary'],
    }),
  }),
});

export const { useGetDashboardSummaryQuery, useGetMyDayQuery } = dashboardApi;
