import { useCallback } from 'react';
import { toast } from 'sonner';
import { useAppSelector } from '@/app/hooks';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useUpdateOwnProfileMutation } from '@/modules/users/api/usersApi';
import type { ProfileFormValues } from '../schema/profileSchema';

// Wraps the cross-module mutation so the settings UI doesn't need to know
// which module owns /users/me. If the backend later splits "own profile"
// into a dedicated /me endpoint, only this hook changes.
export function useProfileForm() {
  const user = useAppSelector((s) => s.auth.user);
  const [updateOwnProfile, state] = useUpdateOwnProfileMutation();

  const initialValues: ProfileFormValues = {
    firstName: user?.firstName ?? '',
    lastName: user?.lastName ?? '',
    email: user?.email ?? '',
  };

  const submit = useCallback(
    async (values: ProfileFormValues) => {
      try {
        await updateOwnProfile(values).unwrap();
        toast.success('Profile updated.');
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't update profile"));
      }
    },
    [updateOwnProfile],
  );

  return { initialValues, submit, isLoading: state.isLoading };
}
