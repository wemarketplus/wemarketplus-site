import { useCallback } from 'react';
import { toast } from 'sonner';
import { useNavigate } from 'react-router-dom';
import { AUTH_REDIRECT_DELAY_MS } from '../constants/authConstants';
import { useAcceptInviteMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { AcceptInviteRequest } from '../types/authTypes';

// Backend behavior caveat: POST /invites/accept consumes the invite token
// only — it marks the invite accepted and returns the invite record. It does
// NOT set the chosen password or return an auth session. So we accept the
// password client-side for UX continuity, consume the token, then send the
// user to /login to sign in. (When the backend ships password-on-accept this
// hook can dispatch setCredentials with the returned tokens instead.)
export function useAcceptInvite(token: string | null) {
  const [acceptInvite, state] = useAcceptInviteMutation();
  const navigate = useNavigate();

  const submit = useCallback(
    async (_password: string) => {
      if (!token) {
        toast.error('This invitation link is invalid or has expired.');
        return;
      }
      try {
        await acceptInvite({ token } satisfies AcceptInviteRequest).unwrap();
        toast.success('Account activated. Please sign in to continue.');
        setTimeout(() => navigate('/login', { replace: true }), AUTH_REDIRECT_DELAY_MS);
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't activate your account"));
      }
    },
    [acceptInvite, navigate, token],
  );

  return { submit, isLoading: state.isLoading };
}
