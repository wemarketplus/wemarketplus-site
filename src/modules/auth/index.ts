// Public surface of the auth module. Internals stay private.
export { AuthPage } from './pages/AuthPage';
export { ForgotPasswordPage } from './pages/ForgotPasswordPage';
export { ResetPasswordPage } from './pages/ResetPasswordPage';
export { AcceptInvitePage } from './pages/AcceptInvitePage';
export { ChangePasswordPage } from './pages/ChangePasswordPage';
export { default as authReducer, setCredentials, logout } from './store/authSlice';
export {
  authApi,
  useLoginMutation,
  useMeQuery,
  useLazyMeQuery,
  useForgotPasswordMutation,
  useResetPasswordMutation,
  useAcceptInviteMutation,
  useChangePasswordMutation,
} from './api/authApi';
export type {
  AuthenticatedUser,
  AuthState,
  LoginRequest,
  LoginResponse,
} from './types/authTypes';
