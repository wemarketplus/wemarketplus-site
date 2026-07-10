import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope, PaginatedPayload } from '@/shared/types';
import { USERS_TAGS } from '../constants/usersConstants';
import type {
  AdminResetPasswordResponse,
  CreateUserRequest,
  ListUsersQuery,
  UpdateOwnProfileRequest,
  UpdateUserRequest,
  UserRecord,
} from '../types/usersTypes';

export const usersApi = createApi({
  reducerPath: 'usersApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [USERS_TAGS.List, USERS_TAGS.Detail],
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
    getUser: build.query<UserRecord, string>({
      query: (id) => ({ url: `/users/${id}` }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      providesTags: (_r, _e, id) => [{ type: USERS_TAGS.Detail, id }],
    }),
    createUser: build.mutation<UserRecord, CreateUserRequest>({
      query: (body) => ({ url: '/users', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      invalidatesTags: [{ type: USERS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    updateUser: build.mutation<UserRecord, { id: string; patch: UpdateUserRequest }>({
      query: ({ id, patch }) => ({ url: `/users/${id}`, method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      invalidatesTags: (_r, _e, { id }) => [
        { type: USERS_TAGS.Detail, id },
        { type: USERS_TAGS.List, id: 'PARTIAL-LIST' },
      ],
    }),
    updateOwnProfile: build.mutation<UserRecord, UpdateOwnProfileRequest>({
      query: (patch) => ({ url: '/users/me', method: 'PATCH', body: patch }),
      transformResponse: (res: ApiEnvelope<UserRecord>) => res.data,
      invalidatesTags: [{ type: USERS_TAGS.List, id: 'PARTIAL-LIST' }],
    }),
    deleteUser: build.mutation<void, string>({
      query: (id) => ({ url: `/users/${id}`, method: 'DELETE' }),
      invalidatesTags: (_r, _e, id) => [
        { type: USERS_TAGS.Detail, id },
        { type: USERS_TAGS.List, id: 'PARTIAL-LIST' },
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
  useGetUserQuery,
  useCreateUserMutation,
  useUpdateUserMutation,
  useUpdateOwnProfileMutation,
  useDeleteUserMutation,
  useAdminResetPasswordMutation,
} = usersApi;
