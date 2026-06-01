import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useResetPasswordMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { ResetPasswordRequest } from '../types/authTypes';

export function useResetPassword(token: string | null) {
  const [resetPassword, state] = useResetPasswordMutation();
  const [done, setDone] = useState(false);
  const navigate = useNavigate();

  const submit = useCallback(
    async (password: string) => {
      if (!token) {
        toast.error('This reset link is invalid or has expired.');
        return;
      }
      try {
        await resetPassword({ token, password } satisfies ResetPasswordRequest).unwrap();
        setDone(true);
        toast.success('Password updated. You can sign in now.');
        setTimeout(() => navigate('/login', { replace: true }), 1500);
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't reset password"));
      }
    },
    [navigate, resetPassword, token],
  );

  return { submit, done, isLoading: state.isLoading };
}
