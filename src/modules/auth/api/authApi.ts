import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import { AUTH_TAGS } from '../constants/authConstants';
import type {
  AcceptInviteRequest,
  AcceptInviteResponse,
  AuthenticatedUser,
  ChangePasswordRequest,
  ForgotPasswordRequest,
  LoginRequest,
  LoginResponse,
  RefreshTokenRequest,
  RegisterRequest,
  ResetPasswordRequest,
} from '../types/authTypes';

// Auth endpoints — all under the backend's /api global prefix. Verified
// against wemarketplus-backend/src/auth/auth.controller.ts:
//   POST /auth/login            -> AuthResponseDto { accessToken, refreshToken?, user }
//   POST /auth/register         -> AuthResponseDto (body requires organizationName)
//   POST /auth/refresh          -> AuthResponseDto
//   POST /auth/logout           -> 204, auth-required
//   POST /auth/forgot-password  -> 202, no body
//   POST /auth/reset-password   -> 200, body { token, newPassword }
//   POST /auth/change-password  -> 200, auth-required, body { currentPassword, newPassword }
//   GET  /auth/me               -> UserResponseDto
// Invite acceptance is served by POST /invites/accept (token only) — there is
// no /auth/accept-invite. It marks the invite consumed and returns the invite
// record; it does NOT set a password or return auth tokens.

export const authApi = createApi({
  reducerPath: 'authApi',
  baseQuery: baseQueryWithReauth,
  tagTypes: [AUTH_TAGS.Me],
  endpoints: (build) => ({
    login: build.mutation<LoginResponse, LoginRequest>({
      query: (body) => ({ url: '/auth/login', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    register: build.mutation<LoginResponse, RegisterRequest>({
      query: (body) => ({ url: '/auth/register', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    refresh: build.mutation<LoginResponse, RefreshTokenRequest>({
      query: (body) => ({ url: '/auth/refresh', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
    }),
    logout: build.mutation<void, void>({
      query: () => ({ url: '/auth/logout', method: 'POST' }),
    }),
    me: build.query<AuthenticatedUser, void>({
      query: () => ({ url: '/auth/me' }),
      transformResponse: (res: ApiEnvelope<AuthenticatedUser>) => res.data,
      providesTags: [AUTH_TAGS.Me],
    }),
    forgotPassword: build.mutation<void, ForgotPasswordRequest>({
      query: (body) => ({ url: '/auth/forgot-password', method: 'POST', body }),
    }),
    resetPassword: build.mutation<void, ResetPasswordRequest>({
      query: (body) => ({ url: '/auth/reset-password', method: 'POST', body }),
    }),
    changePassword: build.mutation<void, ChangePasswordRequest>({
      query: (body) => ({ url: '/auth/change-password', method: 'POST', body }),
    }),
    acceptInvite: build.mutation<AcceptInviteResponse, AcceptInviteRequest>({
      query: (body) => ({ url: '/invites/accept', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<AcceptInviteResponse>) => res.data,
    }),
  }),
});

export const {
  useLoginMutation,
  useRegisterMutation,
  useRefreshMutation,
  useLogoutMutation,
  useMeQuery,
  useLazyMeQuery,
  useForgotPasswordMutation,
  useResetPasswordMutation,
  useChangePasswordMutation,
  useAcceptInviteMutation,
} = authApi;
