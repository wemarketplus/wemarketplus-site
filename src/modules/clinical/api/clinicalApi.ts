import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload, PaginationParams } from '@/shared/types';
import type { BedUnitStatus, TelehealthStatus } from '../constants/clinicalStatus';
import type {
  AlertSetting,
  BedUnitRecord,
  ClockInRequest,
  ClockOutRequest,
  CreateBedUnitRequest,
  CreateGiftGratuityRequest,
  CreateTelehealthSessionRequest,
  EvvLogRecord,
  GiftGratuityRecord,
  TelehealthSessionRecord,
} from '../types/clinicalApiTypes';

// Clinical / field workflows — wemarketplus-backend evv-logs, telehealth-sessions,
// bed-units, gift-gratuity-logs, alert-settings.
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const clinicalApi = createApi({
  reducerPath: 'clinicalApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Evv', 'Telehealth', 'BedUnit', 'Gift', 'AlertSetting'],
  endpoints: (build) => ({
    // EVV
    listEvvLogs: build.query<PaginatedPayload<EvvLogRecord>, (PaginationParams & { userId?: string; prospectId?: string }) | void>({
      query: (p) => ({ url: '/evv-logs', params: p ?? undefined }),
      transformResponse: list<EvvLogRecord>,
      providesTags: ['Evv'],
    }),
    clockIn: build.mutation<EvvLogRecord, ClockInRequest>({
      query: (body) => ({ url: '/evv-logs/clock-in', method: 'POST', body }),
      transformResponse: env<EvvLogRecord>,
      invalidatesTags: ['Evv'],
    }),
    clockOut: build.mutation<EvvLogRecord, { id: string; body: ClockOutRequest }>({
      query: ({ id, body }) => ({ url: `/evv-logs/${id}/clock-out`, method: 'PATCH', body }),
      transformResponse: env<EvvLogRecord>,
      invalidatesTags: ['Evv'],
    }),
    // telehealth
    listTelehealth: build.query<PaginatedPayload<TelehealthSessionRecord>, (PaginationParams & { status?: TelehealthStatus; prospectId?: string }) | void>({
      query: (p) => ({ url: '/telehealth-sessions', params: p ?? undefined }),
      transformResponse: list<TelehealthSessionRecord>,
      providesTags: ['Telehealth'],
    }),
    createTelehealth: build.mutation<TelehealthSessionRecord, CreateTelehealthSessionRequest>({
      query: (body) => ({ url: '/telehealth-sessions', method: 'POST', body }),
      transformResponse: env<TelehealthSessionRecord>,
      invalidatesTags: ['Telehealth'],
    }),
    updateTelehealth: build.mutation<TelehealthSessionRecord, { id: string; patch: Partial<CreateTelehealthSessionRequest> }>({
      query: ({ id, patch }) => ({ url: `/telehealth-sessions/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<TelehealthSessionRecord>,
      invalidatesTags: ['Telehealth'],
    }),
    deleteTelehealth: build.mutation<void, string>({
      query: (id) => ({ url: `/telehealth-sessions/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Telehealth'],
    }),
    // bed units
    listBedUnits: build.query<PaginatedPayload<BedUnitRecord>, (PaginationParams & { status?: BedUnitStatus }) | void>({
      query: (p) => ({ url: '/bed-units', params: p ?? undefined }),
      transformResponse: list<BedUnitRecord>,
      providesTags: ['BedUnit'],
    }),
    createBedUnit: build.mutation<BedUnitRecord, CreateBedUnitRequest>({
      query: (body) => ({ url: '/bed-units', method: 'POST', body }),
      transformResponse: env<BedUnitRecord>,
      invalidatesTags: ['BedUnit'],
    }),
    updateBedUnit: build.mutation<BedUnitRecord, { id: string; patch: Partial<CreateBedUnitRequest> }>({
      query: ({ id, patch }) => ({ url: `/bed-units/${id}`, method: 'PATCH', body: patch }),
      transformResponse: env<BedUnitRecord>,
      invalidatesTags: ['BedUnit'],
    }),
    deleteBedUnit: build.mutation<void, string>({
      query: (id) => ({ url: `/bed-units/${id}`, method: 'DELETE' }),
      invalidatesTags: ['BedUnit'],
    }),
    // gift & gratuity
    listGifts: build.query<PaginatedPayload<GiftGratuityRecord>, PaginationParams | void>({
      query: (p) => ({ url: '/gift-gratuity-logs', params: p ?? undefined }),
      transformResponse: list<GiftGratuityRecord>,
      providesTags: ['Gift'],
    }),
    createGift: build.mutation<GiftGratuityRecord, CreateGiftGratuityRequest>({
      query: (body) => ({ url: '/gift-gratuity-logs', method: 'POST', body }),
      transformResponse: env<GiftGratuityRecord>,
      invalidatesTags: ['Gift'],
    }),
    // alert settings
    getAlertSettings: build.query<AlertSetting[], void>({
      query: () => ({ url: '/alert-settings' }),
      transformResponse: (res: ApiEnvelope<AlertSetting[]>) => res.data,
      providesTags: ['AlertSetting'],
    }),
    upsertAlertSetting: build.mutation<AlertSetting, Partial<AlertSetting> & { alertType: string }>({
      query: (body) => ({ url: '/alert-settings', method: 'PUT', body }),
      transformResponse: env<AlertSetting>,
      invalidatesTags: ['AlertSetting'],
    }),
  }),
});

export const {
  useListEvvLogsQuery,
  useClockInMutation,
  useClockOutMutation,
  useListTelehealthQuery,
  useCreateTelehealthMutation,
  useUpdateTelehealthMutation,
  useDeleteTelehealthMutation,
  useListBedUnitsQuery,
  useCreateBedUnitMutation,
  useUpdateBedUnitMutation,
  useDeleteBedUnitMutation,
  useListGiftsQuery,
  useCreateGiftMutation,
  useGetAlertSettingsQuery,
  useUpsertAlertSettingMutation,
} = clinicalApi;
