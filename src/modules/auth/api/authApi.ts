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
  MfaDisableRequest,
  MfaEnableRequest,
  MfaSetupResponse,
  MfaVerifyRequest,
  RefreshTokenRequest,
  RegisterRequest,
  RegisterResponse,
  ResendVerificationRequest,
  ResetPasswordRequest,
  VerifyEmailRequest,
} from '../types/authTypes';

// Auth endpoints — all under the backend's /api global prefix. Verified
// against wemarketplus-backend/src/auth/auth.controller.ts:
//   POST /auth/login                -> AuthResponseDto { accessToken, refreshToken?, user };
//                                      403 "EMAIL_NOT_VERIFIED" when the password is right
//                                      but the email is still unverified
//   POST /auth/register             -> AuthResponseDto (body requires organizationName).
//                                      When email verification is enforced (production)
//                                      it returns { user, requiresEmailVerification: true }
//                                      with NO tokens; dev still returns tokens.
//   POST /auth/verify-email         -> AuthResponseDto (logs the user in); 401 on
//                                      invalid/expired/reused tokens
//   POST /auth/resend-verification  -> 202 always (enumeration-safe)
//   POST /auth/refresh              -> AuthResponseDto
//   POST /auth/logout               -> 204, auth-required
//   POST /auth/forgot-password      -> 202, no body
//   POST /auth/reset-password       -> 200, body { token, newPassword }
//   POST /auth/change-password      -> 200, auth-required, body { currentPassword, newPassword }
//   POST /auth/mfa/setup            -> 200, auth-required, { otpauthUrl, qrDataUrl, secret }
//   POST /auth/mfa/enable           -> 204, auth-required, body { code }
//   POST /auth/mfa/disable          -> 204, auth-required, body { code } OR { password }
//   POST /auth/mfa/verify           -> 200, PUBLIC, body { mfaToken, code } -> full session;
//                                      the second step after a login that returned
//                                      { mfaRequired: true, mfaToken }
//   GET  /auth/me                   -> UserResponseDto
// Invite acceptance is served by POST /invites/accept { token, password } —
// it sets the invitee's password and returns a full auth session.

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
    register: build.mutation<RegisterResponse, RegisterRequest>({
      query: (body) => ({ url: '/auth/register', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<RegisterResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    verifyEmail: build.mutation<LoginResponse, VerifyEmailRequest>({
      query: (body) => ({ url: '/auth/verify-email', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    resendVerification: build.mutation<void, ResendVerificationRequest>({
      query: (body) => ({ url: '/auth/resend-verification', method: 'POST', body }),
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
    mfaSetup: build.mutation<MfaSetupResponse, void>({
      query: () => ({ url: '/auth/mfa/setup', method: 'POST' }),
      transformResponse: (res: ApiEnvelope<MfaSetupResponse>) => res.data,
    }),
    mfaEnable: build.mutation<void, MfaEnableRequest>({
      query: (body) => ({ url: '/auth/mfa/enable', method: 'POST', body }),
      // Enabling MFA changes the account's security state shown by /auth/me.
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    mfaDisable: build.mutation<void, MfaDisableRequest>({
      query: (body) => ({ url: '/auth/mfa/disable', method: 'POST', body }),
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    mfaVerify: build.mutation<LoginResponse, MfaVerifyRequest>({
      query: (body) => ({ url: '/auth/mfa/verify', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
    acceptInvite: build.mutation<LoginResponse, AcceptInviteRequest>({
      query: (body) => ({ url: '/invites/accept', method: 'POST', body }),
      transformResponse: (res: ApiEnvelope<LoginResponse>) => res.data,
      invalidatesTags: [AUTH_TAGS.Me],
    }),
  }),
});

export const {
  useLoginMutation,
  useRegisterMutation,
  useVerifyEmailMutation,
  useResendVerificationMutation,
  useRefreshMutation,
  useLogoutMutation,
  useMeQuery,
  useLazyMeQuery,
  useForgotPasswordMutation,
  useResetPasswordMutation,
  useChangePasswordMutation,
  useMfaSetupMutation,
  useMfaEnableMutation,
  useMfaDisableMutation,
  useMfaVerifyMutation,
  useAcceptInviteMutation,
} = authApi;
