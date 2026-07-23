import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  AlertSettingRecord,
  FinancialSettingRecord,
  UpsertAlertSettingRequest,
  UpsertFinancialSettingRequest,
} from '../types/adminSettingsApiTypes';

// wemarketplus-backend/src/alert-settings + src/mileage/financial-settings.controller.ts.
// Both GET endpoints return a plain array (not the paginated envelope the CL
// list endpoints use); PUT/upsert is Admin/Owner-only server-side.
export const adminSettingsApi = createApi({
  reducerPath: 'clAdminSettingsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['AlertSetting', 'FinancialSetting'],
  endpoints: (build) => ({
    listAlertSettings: build.query<AlertSettingRecord[], void>({
      query: () => ({ url: '/alert-settings' }),
      transformResponse: (res: ApiEnvelope<AlertSettingRecord[]>) => res.data,
      providesTags: ['AlertSetting'],
    }),
    upsertAlertSetting: build.mutation<AlertSettingRecord, UpsertAlertSettingRequest>({
      query: (body) => ({ url: '/alert-settings', method: 'PUT', body }),
      transformResponse: (res: ApiEnvelope<AlertSettingRecord>) => res.data,
      invalidatesTags: ['AlertSetting'],
    }),
    listFinancialSettings: build.query<FinancialSettingRecord[], void>({
      query: () => ({ url: '/financial-settings' }),
      transformResponse: (res: ApiEnvelope<FinancialSettingRecord[]>) => res.data,
      providesTags: ['FinancialSetting'],
    }),
    upsertFinancialSetting: build.mutation<FinancialSettingRecord, UpsertFinancialSettingRequest>({
      query: (body) => ({ url: '/financial-settings', method: 'PUT', body }),
      transformResponse: (res: ApiEnvelope<FinancialSettingRecord>) => res.data,
      invalidatesTags: ['FinancialSetting'],
    }),
  }),
});

export const {
  useListAlertSettingsQuery,
  useUpsertAlertSettingMutation,
  useListFinancialSettingsQuery,
  useUpsertFinancialSettingMutation,
} = adminSettingsApi;
