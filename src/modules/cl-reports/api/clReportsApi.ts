import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type { ClReportResult } from '../types/clReportsTypes';

// CommunityLink Reports — computed live from cl_* data by the backend
// (wemarketplus-backend cl/reports). Distinct from the static REPORT_CATALOG
// fixture, which now only supplies card metadata (title/description/category).
export const clReportsApi = createApi({
  reducerPath: 'clReportsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['ClReport'],
  endpoints: (build) => ({
    listClReports: build.query<ClReportResult[], void>({
      query: () => ({ url: '/cl/reports' }),
      transformResponse: (res: ApiEnvelope<ClReportResult[]>) => res.data,
      providesTags: ['ClReport'],
    }),
  }),
});

export const { useListClReportsQuery } = clReportsApi;
