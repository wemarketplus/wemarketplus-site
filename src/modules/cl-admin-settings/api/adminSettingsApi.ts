import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import type {
  AlertChannelAvailability,
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
    // Deployment capability, not tenant data — which channels can actually
    // deliver. Admin/Owner-only server-side, same as the write route.
    listAlertChannels: build.query<AlertChannelAvailability[], void>({
      query: () => ({ url: '/alert-settings/channels' }),
      transformResponse: (res: ApiEnvelope<AlertChannelAvailability[]>) => res.data,
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
  useListAlertChannelsQuery,
  useUpsertAlertSettingMutation,
  useListFinancialSettingsQuery,
  useUpsertFinancialSettingMutation,
} = adminSettingsApi;
