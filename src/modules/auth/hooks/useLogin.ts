import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { extractApiErrorMessage } from '../utils/errorUtils';
import { useLoginMutation, useMfaVerifyMutation } from '../api/authApi';
import { setCredentials } from '../store/authSlice';
import { useResendVerification } from './useResendVerification';
import type { AuthenticatedUser, LoginResponse, LoginRequest } from '../types/authTypes';

export function useLogin() {
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const [login, state] = useLoginMutation();
  const [mfaVerify, mfaState] = useMfaVerifyMutation();
  const { resend, isLoading: isResending } = useResendVerification();
  // Set when the backend rejects a correct password with 403
  // EMAIL_NOT_VERIFIED — the page swaps the generic error toast for a
  // verify-your-email message with a resend button.
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  // Set when login returns { mfaRequired, mfaToken }: the page swaps the
  // password form for a 6-digit code step. Cleared on cancel or success.
  const [mfaToken, setMfaToken] = useState<string | null>(null);

  // Completes a login by storing the session and navigating home. Shared by the
  // plain path and the MFA second step.
  const finish = useCallback(
    (result: LoginResponse) => {
      const user = result.user as AuthenticatedUser;
      dispatch(
        setCredentials({
          token: result.accessToken ?? null,
          refreshToken: result.refreshToken ?? null,
          user,
        }),
      );
      toast.success(`Welcome back, ${user.firstName}`);
      navigate('/', { replace: true });
    },
    [dispatch, navigate],
  );

  const submit = useCallback(
    async (values: LoginRequest) => {
      setUnverifiedEmail(null);
      setMfaToken(null);
      try {
        const result = await login(values).unwrap();
        // MFA-enabled accounts get no tokens here — hold for the code step.
        if (result.mfaRequired && result.mfaToken) {
          setMfaToken(result.mfaToken);
          return;
        }
        finish(result);
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
    [finish, login],
  );

  // Second step: submit the 6-digit code with the held mfaToken.
  const submitMfaCode = useCallback(
    async (code: string) => {
      if (!mfaToken) return;
      try {
        const result = await mfaVerify({ mfaToken, code }).unwrap();
        setMfaToken(null);
        finish(result);
      } catch (err) {
        toast.error(extractApiErrorMessage(err, 'Invalid authentication code'));
      }
    },
    [finish, mfaToken, mfaVerify],
  );

  // Abandon the MFA step and return to the password form.
  const cancelMfa = useCallback(() => setMfaToken(null), []);

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
    // MFA second-step state/handlers.
    mfaRequired: mfaToken !== null,
    submitMfaCode,
    cancelMfa,
    isVerifyingMfa: mfaState.isLoading,
  };
}
