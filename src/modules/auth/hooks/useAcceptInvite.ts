import { useCallback } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { useAcceptInviteMutation } from '../api/authApi';
import { AUTH_REDIRECT_DELAY_MS } from '../constants/authConstants';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { AcceptInviteRequest } from '../types/authTypes';

// POST /invites/accept consumes the invite token and sets the chosen password.
// It does NOT return a session and we deliberately do NOT auto-login: per OWASP
// guidance, after setting a password from an emailed link the user should sign
// in through the normal login flow (auto-login adds session-handling complexity
// and a login-CSRF surface). On success we send them to /login to sign in.
export function useAcceptInvite(token: string | null) {
  const [acceptInvite, state] = useAcceptInviteMutation();
  const navigate = useNavigate();

  const submit = useCallback(
    async (password: string) => {
      if (!token) {
        toast.error('This invitation link is invalid or has expired.');
        return;
      }
      try {
        await acceptInvite(
          { token, password } satisfies AcceptInviteRequest,
        ).unwrap();
        toast.success('Account activated. Please sign in with your new password.');
        setTimeout(() => navigate('/login', { replace: true }), AUTH_REDIRECT_DELAY_MS);
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't activate your account"));
      }
    },
    [acceptInvite, navigate, token],
  );

  return { submit, isLoading: state.isLoading };
}
