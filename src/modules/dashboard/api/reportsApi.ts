import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { ReportSummary } from '../types/reportsTypes';

// Backend reports — wemarketplus-backend/src/reports.
//   GET /reports/summary     -> ReportSummaryDto (tenant-scoped KPI aggregate)
//   GET /reports/export/pdf  -> application/pdf (download via utils/reportPdfUrl)
export const reportsApi = createApi({
  reducerPath: 'reportsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ReportSummary'],
  endpoints: (build) => ({
    getReportSummary: build.query<ReportSummary, void>({
      query: () => ({ url: '/reports/summary' }),
      transformResponse: (res: ApiEnvelope<ReportSummary>) => res.data,
      providesTags: ['ReportSummary'],
    }),
  }),
});

export const { useGetReportSummaryQuery } = reportsApi;
