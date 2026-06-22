import { useCallback } from 'react';
import { toast } from 'sonner';
import { useChangePasswordMutation } from '../api/authApi';
import { extractApiErrorMessage } from '../utils/errorUtils';
import type { ChangePasswordFormInput } from '../types/authTypes';

export function useChangePassword() {
  const [changePassword, state] = useChangePasswordMutation();

  const submit = useCallback(
    async (values: ChangePasswordFormInput, onSuccess?: () => void) => {
      try {
        await changePassword({
          currentPassword: values.currentPassword,
          newPassword: values.password,
        }).unwrap();
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
