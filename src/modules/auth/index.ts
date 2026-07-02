// Public surface of the auth module. Internals stay private.
export { AuthPage } from './pages/AuthPage';
export { ForgotPasswordPage } from './pages/ForgotPasswordPage';
export { ResetPasswordPage } from './pages/ResetPasswordPage';
export { AcceptInvitePage } from './pages/AcceptInvitePage';
export { VerifyEmailPage } from './pages/VerifyEmailPage';
export { ChangePasswordPage } from './pages/ChangePasswordPage';
export { useResendVerification } from './hooks/useResendVerification';
export { default as authReducer, setCredentials, logout } from './store/authSlice';
export {
  authApi,
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
  useAcceptInviteMutation,
} from './api/authApi';
export type {
  AuthenticatedUser,
  AuthState,
  LoginRequest,
  LoginResponse,
  RegisterResponse,
} from './types/authTypes';
