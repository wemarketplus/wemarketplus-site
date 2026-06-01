import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, AppNotification } from '@/shared/types';
import { NOTIFICATIONS_TAGS } from '../constants/notificationsConstants';

// TODO(backend): ship GET /notifications, POST /notifications/:id/read,
// POST /notifications/mark-all-read. Hook is wired with a fixture fallback in
// useNotifications.
export const notificationsApi = createApi({
  reducerPath: 'notificationsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [NOTIFICATIONS_TAGS.List],
  endpoints: (build) => ({
    listNotifications: build.query<readonly AppNotification[], void>({
      query: () => ({ url: '/notifications' }),
      transformResponse: (res: ApiEnvelope<readonly AppNotification[]>) => res.data,
      providesTags: [NOTIFICATIONS_TAGS.List],
    }),
    markRead: build.mutation<void, string>({
      query: (id) => ({ url: `/notifications/${id}/read`, method: 'POST' }),
      invalidatesTags: [NOTIFICATIONS_TAGS.List],
    }),
    markAllRead: build.mutation<void, void>({
      query: () => ({ url: '/notifications/mark-all-read', method: 'POST' }),
      invalidatesTags: [NOTIFICATIONS_TAGS.List],
    }),
  }),
});

export const {
  useListNotificationsQuery,
  useMarkReadMutation,
  useMarkAllReadMutation,
} = notificationsApi;
