import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { APPOINTMENTS_TAGS } from '../constants/appointmentsConstants';
import type {
  AppointmentRecord,
  CalendarQuery,
  CompleteAppointmentRequest,
  CreateAppointmentRequest,
  ListAppointmentsQuery,
  UpdateAppointmentRequest,
} from '../types/appointmentsTypes';

// Verified against wemarketplus-backend/src/appointments/appointments.controller.ts:
//   GET    /hl/appointments?page&limit&jobId&assignedRep&status&appointmentType&outcome
//   GET    /hl/appointments/calendar?from&to&assignedRep -> AppointmentResponseDto[]
//   GET    /hl/appointments/:id
//   POST   /hl/appointments
//   PATCH  /hl/appointments/:id
//   POST   /hl/appointments/:id/complete   (chains the next job best-effort)
//   DELETE /hl/appointments/:id            (admin/owner/manager only)
const env = <T>(res: ApiEnvelope<T>) => res.data;
const list = <T>(res: ApiEnvelope<PaginatedPayload<T>>) => res.data;

export const appointmentsApi = createApi({
  reducerPath: 'appointmentsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [
    APPOINTMENTS_TAGS.List,
    APPOINTMENTS_TAGS.Detail,
    APPOINTMENTS_TAGS.Calendar,
  ],
  endpoints: (build) => ({
    listAppointments: build.query<
      PaginatedPayload<AppointmentRecord>,
      ListAppointmentsQuery | void
    >({
      query: (params) => ({
        url: '/hl/appointments',
        params: params ?? undefined,
      }),
      transformResponse: list<AppointmentRecord>,
      providesTags: [{ type: APPOINTMENTS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    // The calendar feed returns a bare array (not paginated).
    getCalendar: build.query<AppointmentRecord[], CalendarQuery>({
      query: (params) => ({ url: '/hl/appointments/calendar', params }),
      transformResponse: env<AppointmentRecord[]>,
      providesTags: [{ type: APPOINTMENTS_TAGS.Calendar, id: 'WINDOW' }],
    }),
    getAppointment: build.query<AppointmentRecord, string>({
      query: (id) => ({ url: `/hl/appointments/${id}` }),
      transformResponse: env<AppointmentRecord>,
      providesTags: (_r, _e, id) => [{ type: APPOINTMENTS_TAGS.Detail, id }],
    }),
    createAppointment: build.mutation<
      AppointmentRecord,
      CreateAppointmentRequest
    >({
      query: (body) => ({ url: '/hl/appointments', method: 'POST', body }),
      transformResponse: env<AppointmentRecord>,
      invalidatesTags: [
        { type: APPOINTMENTS_TAGS.List, id: 'PARTIAL-LIST' },
        { type: APPOINTMENTS_TAGS.Calendar, id: 'WINDOW' },
      ],
    }),
    updateAppointment: build.mutation<
      AppointmentRecord,
      { id: string; patch: UpdateAppointmentRequest }
    >({
      query: ({ id, patch }) => ({
        url: `/hl/appointments/${id}`,
        method: 'PATCH',
        body: patch,
      }),
      transformResponse: env<AppointmentRecord>,
      invalidatesTags: (_r, _e, { id }) => [
        { type: APPOINTMENTS_TAGS.Detail, id },
        { type: APPOINTMENTS_TAGS.List, id: 'PARTIAL-LIST' },
        { type: APPOINTMENTS_TAGS.Calendar, id: 'WINDOW' },
      ],
    }),
    completeAppointment: build.mutation<
      AppointmentRecord,
      { id: string; body: CompleteAppointmentRequest }
    >({
      query: ({ id, body }) => ({
        url: `/hl/appointments/${id}/complete`,
        method: 'POST',
        body,
      }),
      transformResponse: env<AppointmentRecord>,
      invalidatesTags: (_r, _e, { id }) => [
        { type: APPOINTMENTS_TAGS.Detail, id },
        { type: APPOINTMENTS_TAGS.List, id: 'PARTIAL-LIST' },
        { type: APPOINTMENTS_TAGS.Calendar, id: 'WINDOW' },
      ],
    }),
    deleteAppointment: build.mutation<void, string>({
      query: (id) => ({ url: `/hl/appointments/${id}`, method: 'DELETE' }),
      invalidatesTags: [
        { type: APPOINTMENTS_TAGS.List, id: 'PARTIAL-LIST' },
        { type: APPOINTMENTS_TAGS.Calendar, id: 'WINDOW' },
      ],
    }),
  }),
});

export const {
  useListAppointmentsQuery,
  useGetCalendarQuery,
  useGetAppointmentQuery,
  useCreateAppointmentMutation,
  useUpdateAppointmentMutation,
  useCompleteAppointmentMutation,
  useDeleteAppointmentMutation,
} = appointmentsApi;
