import { useCallback } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { useAcceptInviteMutation } from '../api/authApi';
import { setCredentials } from '../store/authSlice';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { AcceptInviteRequest } from '../types/authTypes';

export function useAcceptInvite(token: string | null) {
  const [acceptInvite, state] = useAcceptInviteMutation();
  const dispatch = useAppDispatch();
  const navigate = useNavigate();

  const submit = useCallback(
    async (password: string) => {
      if (!token) {
        toast.error('This invitation link is invalid or has expired.');
        return;
      }
      try {
        const result = await acceptInvite({
          token,
          password,
        } satisfies AcceptInviteRequest).unwrap();
        dispatch(setCredentials({ token: result.accessToken, user: result.user }));
        toast.success(`Welcome aboard, ${result.user.firstName}`);
        navigate('/', { replace: true });
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't activate your account"));
      }
    },
    [acceptInvite, dispatch, navigate, token],
  );

  return { submit, isLoading: state.isLoading };
}
