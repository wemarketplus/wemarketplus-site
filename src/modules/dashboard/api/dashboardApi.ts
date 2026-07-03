import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { DashboardSummary } from '../types/dashboardTypes';

// Backend dashboard — wemarketplus-backend/src/dashboard.
//   GET /dashboard/summary -> DashboardSummaryDto (tenant-scoped KPI aggregate:
//   prospects by stage, open tasks, overdue/outstanding invoices, unread
//   notifications, recent activity). Recent activity is folded into the summary.
export const dashboardApi = createApi({
  reducerPath: 'dashboardApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['DashboardSummary'],
  endpoints: (build) => ({
    getDashboardSummary: build.query<DashboardSummary, void>({
      query: () => ({ url: '/dashboard/summary' }),
      transformResponse: (res: ApiEnvelope<DashboardSummary>) => res.data,
      providesTags: ['DashboardSummary'],
    }),
  }),
});

export const { useGetDashboardSummaryQuery } = dashboardApi;
