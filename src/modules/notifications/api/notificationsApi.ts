import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { NOTIFICATIONS_TAGS } from '../constants/notificationsConstants';
import type {
  ListNotificationsQuery,
  NotificationPreferencesResponse,
  NotificationRecord,
  RespondNotificationRequest,
  UnreadCountResponse,
  UpdateNotificationPreferencesRequest,
} from '../types/notificationsTypes';

// Verified against wemarketplus-backend/src/notifications/notifications.controller.ts:
//   GET   /notifications?page&limit&unreadOnly -> PaginatedResult<NotificationResponseDto>
//   GET   /notifications/unread-count          -> { count }
//   PATCH /notifications/:id/read              -> NotificationResponseDto
//   POST  /notifications/mark-all-read         -> { updated }
//   POST  /notifications/:id/respond           -> NotificationResponseDto, body { action }
//   GET   /notifications/preferences           -> { items: [{ type, inApp }] }
//   PUT   /notifications/preferences           -> { items }, body { items }
export const notificationsApi = createApi({
  reducerPath: 'notificationsApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [NOTIFICATIONS_TAGS.List, NOTIFICATIONS_TAGS.Preferences],
  endpoints: (build) => ({
    listNotifications: build.query<PaginatedPayload<NotificationRecord>, ListNotificationsQuery | void>({
      query: (params) => ({ url: '/notifications', params: params ?? undefined }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<NotificationRecord>>) => res.data,
      providesTags: [NOTIFICATIONS_TAGS.List],
    }),
    unreadCount: build.query<number, void>({
      query: () => ({ url: '/notifications/unread-count' }),
      transformResponse: (res: ApiEnvelope<UnreadCountResponse>) => res.data.count,
      providesTags: [NOTIFICATIONS_TAGS.List],
    }),
    markRead: build.mutation<NotificationRecord, string>({
      query: (id) => ({ url: `/notifications/${id}/read`, method: 'PATCH' }),
      transformResponse: (res: ApiEnvelope<NotificationRecord>) => res.data,
      invalidatesTags: [NOTIFICATIONS_TAGS.List],
    }),
    markAllRead: build.mutation<{ updated: number }, void>({
      query: () => ({ url: '/notifications/mark-all-read', method: 'POST' }),
      transformResponse: (res: ApiEnvelope<{ updated: number }>) => res.data,
      invalidatesTags: [NOTIFICATIONS_TAGS.List],
    }),
    respond: build.mutation<NotificationRecord, RespondNotificationRequest>({
      query: ({ id, action }) => ({
        url: `/notifications/${id}/respond`,
        method: 'POST',
        body: { action },
      }),
      transformResponse: (res: ApiEnvelope<NotificationRecord>) => res.data,
      invalidatesTags: [NOTIFICATIONS_TAGS.List],
    }),
    getPreferences: build.query<NotificationPreferencesResponse, void>({
      query: () => ({ url: '/notifications/preferences' }),
      transformResponse: (res: ApiEnvelope<NotificationPreferencesResponse>) => res.data,
      providesTags: [NOTIFICATIONS_TAGS.Preferences],
    }),
    updatePreferences: build.mutation<
      NotificationPreferencesResponse,
      UpdateNotificationPreferencesRequest
    >({
      query: (body) => ({
        url: '/notifications/preferences',
        method: 'PUT',
        body,
      }),
      transformResponse: (res: ApiEnvelope<NotificationPreferencesResponse>) => res.data,
      // Optimistic: patch the cached preferences immediately, roll back on error.
      async onQueryStarted(body, { dispatch, queryFulfilled }) {
        const patch = dispatch(
          notificationsApi.util.updateQueryData('getPreferences', undefined, (draft) => {
            for (const update of body.items) {
              const existing = draft.items.find((i) => i.type === update.type);
              if (existing) existing.inApp = update.inApp;
            }
          }),
        );
        try {
          await queryFulfilled;
        } catch {
          patch.undo();
        }
      },
      invalidatesTags: [NOTIFICATIONS_TAGS.Preferences],
    }),
  }),
});

export const {
  useListNotificationsQuery,
  useUnreadCountQuery,
  useMarkReadMutation,
  useMarkAllReadMutation,
  useRespondMutation,
  useGetPreferencesQuery,
  useUpdatePreferencesMutation,
} = notificationsApi;
