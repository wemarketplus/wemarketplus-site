import { createApi } from '@reduxjs/toolkit/query/react';
import { baseQueryWithReauth } from '@/app/baseQuery';
import type { ApiEnvelope } from '@/shared/types';
import { AUTH_TAGS } from '../constants/authConstants';
import type {
  AcceptInviteRequest,
  AuthenticatedUser,
  ChangePasswordRequest,
  ForgotPasswordRequest,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  ResetPasswordRequest,
} from '../types/authTypes';

// Auth endpoints. login/register/me are live against the NestJS backend.
// The password-flow endpoints (forgot/reset/accept-invite/change-password)
// are declared with the URLs the site already uses; the backend has not
// shipped them yet. They will compile and the UI will call them — they'll
// just 404 until the backend route exists.
// TODO(backend): ship /auth/forgot-password, /auth/reset-password,
// /auth/accept-invite, /auth/change-password mirroring the request DTOs in
// `@/modules/auth/types/authTypes`.

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
    }),
    me: build.query<AuthenticatedUser, void>({
      query: () => ({ url: '/auth/me' }),
      transformResponse: (res: ApiEnvelope<AuthenticatedUser>) => res.data,
      providesTags: [AUTH_TAGS.Me],
    }),
    forgotPassword: build.mutation<{ requested: boolean }, ForgotPasswordRequest>({
      query: (body) => ({ url: '/auth/forgot-password', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<{ requested: boolean }>) => res.data,
    }),
    resetPassword: build.mutation<{ reset: boolean }, ResetPasswordRequest>({
      query: (body) => ({ url: '/auth/reset-password', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<{ reset: boolean }>) => res.data,
    }),
    acceptInvite: build.mutation<LoginResponse, AcceptInviteRequest>({
      query: (body) => ({ url: '/auth/accept-invite', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    changePassword: build.mutation<{ changed: boolean }, ChangePasswordRequest>({
      query: (body) => ({ url: '/auth/change-password', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<{ changed: boolean }>) => res.data,
    }),
  }),
});

export const {
  useLoginMutation,
  useRegisterMutation,
  useMeQuery,
  useLazyMeQuery,
  useForgotPasswordMutation,
  useResetPasswordMutation,
  useAcceptInviteMutation,
  useChangePasswordMutation,
} = authApi;
