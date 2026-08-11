import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { USERS_TAGS } from '../constants/usersConstants';
import type {
  AdminResetPasswordResponse,
  CalendarColorRecord,
  CreateUserRequest,
  ListUsersQuery,
  UpdateOwnProfileRequest,
  UpdateUserRequest,
  SeatUsage,
  UserRecord,
} from '../types/usersTypes';

export const usersApi = createApi({
  reducerPath: 'usersApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [
    USERS_TAGS.List,
    USERS_TAGS.Detail,
    USERS_TAGS.CalendarColors,
    USERS_TAGS.Seats,
  ],
  endpoints: (build) => ({
    listUsers: build.query<PaginatedPayload<UserRecord>, ListUsersQuery>({
      query: (params = {}) => ({ url: '/users', params }),
      transformResponse: (res: ApiEnvelope<PaginatedPayload<UserRecord>>) => res.data,
      providesTags: (result) =>
        result
          ? [
              ...result.data.map((u) => ({ type: USERS_TAGS.Detail, id: u.id }) as const),
              { type: USERS_TAGS.List, id: 'PARTIAL-LIST' },
            ]
          : [{ type: USERS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    // Admin/Owner only server-side; the Team page renders it behind a RoleGate so
    // a Manager (who may read the list) never fires a request that would 403.
    getSeatUsage: build.query<SeatUsage, void>({
      query: () => ({ url: '/users/seats' }),
      transformResponse: (res: ApiEnvelope<SeatUsage>) => res.data,
      providesTags: [USERS_TAGS.Seats],
    }),
    getUser: build.query<UserRecord, string>({
      query: (id) => ({ url: `/users/${id}` }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      providesTags: (_r, _e, id) => [{ type: USERS_TAGS.Detail, id }],
    }),
    createUser: build.mutation<UserRecord, CreateUserRequest>({
      query: (body) => ({ url: '/users', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      // Seats too: a new user consumes one, and the counter must move with it.
      invalidatesTags: [{ type: USERS_TAGS.List, id: 'PARTIAL-LIST' }, USERS_TAGS.Seats],
    }),
    updateUser: build.mutation<UserRecord, { id: string; patch: UpdateUserRequest }>({
      query: ({ id, patch }) => ({ url: `/users/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      invalidatesTags: (_r, _e, { id }) => [
        { type: USERS_TAGS.Detail, id },
        { type: USERS_TAGS.List, id: 'PARTIAL-LIST' },
        // Deactivating a user frees a seat — `used` counts ACTIVE users only.
        USERS_TAGS.Seats,
      ],
    }),
    // Every authenticated role may call this — it is the one write endpoint a
    // Marketer or Nurse has, and it can only ever touch their own record.
    updateOwnProfile: build.mutation<UserRecord, UpdateOwnProfileRequest>({
      query: (patch) => ({ url: '/users/me', method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      // Invalidating CalendarColors is what repaints the Appointments "All
      // users" calendar the moment a colour is saved, with no page reload: RTK
      // Query refetches the map for whatever screen is currently mounted.
      invalidatesTags: [
        { type: USERS_TAGS.List, id: 'PARTIAL-LIST' },
        USERS_TAGS.CalendarColors,
      ],
    }),
    // id -> chosen colour for the whole tenant. Unpaginated by design: the
    // calendar needs a complete lookup or a colleague's row silently falls back
    // to the derived colour. Bounded server-side.
    listCalendarColors: build.query<CalendarColorRecord[], void>({
      query: () => ({ url: '/users/calendar-colors' }),
      transformResponse: (res: ApiEnvelope<CalendarColorRecord[]>) => res.data,
      providesTags: [USERS_TAGS.CalendarColors],
    }),
    deleteUser: build.mutation<void, string>({
      query: (id) => ({ url: `/users/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: USERS_TAGS.Detail, id },
        { type: USERS_TAGS.List, id: 'PARTIAL-LIST' },
        USERS_TAGS.Seats,
      ],
    }),
    // Admin resets another user's password; backend returns a one-time
    // temporary password to relay to the user (no request body).
    adminResetPassword: build.mutation<AdminResetPasswordResponse, string>({
      query: (id) => ({ url: `/users/${id}/reset-password`, method: 'POST' }),
      transformResponse: (res: ApiEnvelope<AdminResetPasswordResponse>) => res.data,
    }),
  }),
});

export const {
  useListUsersQuery,
  useGetSeatUsageQuery,
  useGetUserQuery,
  useCreateUserMutation,
  useUpdateUserMutation,
  useUpdateOwnProfileMutation,
  useListCalendarColorsQuery,
  useDeleteUserMutation,
  useAdminResetPasswordMutation,
} = usersApi;
