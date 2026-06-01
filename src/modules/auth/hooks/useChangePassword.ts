import { useCallback } from 'react';
import { toast } from 'sonner';
import { useChangePasswordMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { ChangePasswordRequest } from '../types/authTypes';

export function useChangePassword() {
  const [changePassword, state] = useChangePasswordMutation();

  const submit = useCallback(
    async (values: ChangePasswordRequest, onSuccess?: () => void) => {
      try {
        await changePassword(values).unwrap();
        toast.success('Password updated.');
        onSuccess?.();
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't update password"));
      }
    },
    [changePassword],
  );

  return { submit, isLoading: state.isLoading };
}
