import { useCallback } from 'react';
import { toast } from 'sonner';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { patchUser } from '@/modules/auth';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useUpdateOwnProfileMutation } from '@/modules/users/api/usersApi';
import type { ProfileFormValues } from '../schema/profileSchema';

// Wraps the cross-module mutation so the settings UI doesn't need to know
// which module owns /users/me. If the backend later splits "own profile"
// into a dedicated /me endpoint, only this hook changes.
export function useProfileForm() {
  const dispatch = useAppDispatch();
  const user = useAppSelector((s) => s.auth.user);
  const [updateOwnProfile, state] = useUpdateOwnProfileMutation();

  const initialValues: ProfileFormValues = {
    firstName: user?.firstName ?? '',
    lastName: user?.lastName ?? '',
    email: user?.email ?? '',
    phone: user?.phone ?? '',
  };

  const submit = useCallback(
    async (values: ProfileFormValues) => {
      try {
        const saved = await updateOwnProfile(values).unwrap();
        // Fold the saved values back into the cached session user, so the
        // header avatar/name and anything else reading `auth.user` update
        // immediately instead of waiting for the next /auth/me. patchUser
        // MERGES — see the reducer for why replacing would be a bug.
        dispatch(
          patchUser({
            firstName: saved.firstName,
            lastName: saved.lastName,
            email: saved.email,
            phone: saved.phone,
          }),
        );
        toast.success('Profile updated.');
      } catch (err) {
        toast.error(extractApiErrorMessage(err, "Couldn't update profile"));
      }
    },
    [dispatch, updateOwnProfile],
  );

  return { initialValues, submit, isLoading: state.isLoading };
}
