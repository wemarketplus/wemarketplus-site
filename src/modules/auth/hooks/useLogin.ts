import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { extractApiErrorMessage } from '../utils/errorUtils';
import { useLoginMutation } from '../api/authApi';
import { setCredentials } from '../store/authSlice';
import { useResendVerification } from './useResendVerification';
import type { LoginRequest } from '../types/authTypes';

export function useLogin() {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [login, state] = useLoginMutation();
  const { resend, isLoading: isResending } = useResendVerification();
  // Set when the backend rejects a correct password with 403
  // EMAIL_NOT_VERIFIED — the page swaps the generic error toast for a
  // verify-your-email message with a resend button.
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);

  const submit = useCallback(
    async (values: LoginRequest) => {
      setUnverifiedEmail(null);
      try {
        const result = await login(values).unwrap();
        dispatch(
          setCredentials({
            token: result.accessToken ?? null,
            refreshToken: result.refreshToken ?? null,
            user: result.user,
          }),
        );
        toast.success(`Welcome back, ${result.user.firstName}`);
        navigate('/', { replace: true });
      } catch (err) {
        const status = (err as { status?: number })?.status;
        const message = extractApiErrorMessage(err, 'Login failed');
        if (status === 403 && message.includes('EMAIL_NOT_VERIFIED')) {
          setUnverifiedEmail(values.email);
          return;
        }
        toast.error(message);
      }
    },
    [dispatch, login, navigate],
  );

  const resendVerification = useCallback(async () => {
    if (!unverifiedEmail) return;
    await resend(unverifiedEmail);
  }, [resend, unverifiedEmail]);

  return {
    submit,
    isLoading: state.isLoading,
    unverifiedEmail,
    resendVerification,
    isResending,
  };
}
