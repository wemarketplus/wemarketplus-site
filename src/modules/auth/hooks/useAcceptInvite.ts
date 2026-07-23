import { useCallback } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { useStartCheckout } from '@/modules/billing/hooks/useStartCheckout';
import { useAcceptInviteMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import { commitAuthSession } from '../utils/authSession';
import type { AcceptInviteRequest } from '../types/authTypes';

// POST /invites/accept consumes the invite token, sets the chosen password,
// and returns an authenticated session (access/refresh tokens + user data).
// The invitation proves ownership of the email, so we authenticate the user
// immediately and redirect them into the dashboard.
export function useAcceptInvite(token: string | null) {
  const [acceptInvite, state] = useAcceptInviteMutation();
  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { startCheckout } = useStartCheckout();

  const submit = useCallback(
    async (password: string) => {
      if (!token) {
        toast.error('This invitation link is invalid or has expired.');
        return;
      }
      try {
        const result = await acceptInvite(
          { token, password } satisfies AcceptInviteRequest,
        ).unwrap();
        commitAuthSession({
          dispatch,
          navigate,
          result,
          startCheckout,
          welcomeLabel: 'Welcome',
        });
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't activate your account"));
      }
    },
    [acceptInvite, dispatch, navigate, startCheckout, token],
  );

  return { submit, isLoading: state.isLoading };
}
