import { useCallback } from 'react';
import { toast } from 'sonner';
import { useResendVerificationMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { ResendVerificationRequest } from '../types/authTypes';

// Re-sends the email-verification link. The backend answers 202 whether or
// not the address exists (enumeration-safe), so success just means "sent if
// registered" — mirror that in the toast copy.
export function useResendVerification() {
  const [resendVerification, state] = useResendVerificationMutation();

  const resend = useCallback(
    async (email: string) => {
      try {
        await resendVerification({ email } satisfies ResendVerificationRequest).unwrap();
        toast.success('Verification email sent — check your inbox.');
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't send the verification email"));
      }
    },
    [resendVerification],
  );

  return { resend, isLoading: state.isLoading };
}
