import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useForgotPasswordMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { ForgotPasswordRequest } from '../types/authTypes';

export function useForgotPassword() {
  const [forgotPassword, state] = useForgotPasswordMutation();
  const [submitted, setSubmitted] = useState(false);

  const submit = useCallback(
    async (values: ForgotPasswordRequest) => {
      try {
        await forgotPassword(values).unwrap();
        setSubmitted(true);
      } catch (err) {
        // Avoid leaking whether the email exists — show success either way,
        // but still toast on transport errors (500, network).
        const status = (err as { status?: number })?.status;
        if (typeof status === 'number' && status >= 500) {
          toast.error(extractApiErrorMessage(err, "Couldn't send reset email"));
        } else {
          setSubmitted(true);
        }
      }
    },
    [forgotPassword],
  );

  return { submit, submitted, isLoading: state.isLoading };
}
