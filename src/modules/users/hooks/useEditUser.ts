import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useUpdateUserMutation } from '../api/usersApi';
import type { EditUserFormValues } from '../schema/usersSchema';
import type { UpdateUserRequest, UserRecord } from '../types/usersTypes';
import { fullName } from '../utils/userDisplay';

// Orchestrates the Edit-user modal: which user is being edited, open/close
// state, and the PATCH /users/:id mutation. RTK Query invalidates the user's
// detail + list tags on success, so the row updates without a manual refetch.
// Update failures (last-admin, can't-disable-self, permissions) are exposed via
// `submitError` so the modal shows the API message verbatim.
export function useEditUser() {
  const [target, setTarget] = useState<UserRecord | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [updateUser, { isLoading: isSaving }] = useUpdateUserMutation();

  const submit = async (values: EditUserFormValues): Promise<boolean> => {
    if (!target) return false;
    setSubmitError(null);

    const patch: UpdateUserRequest = {
      firstName: values.firstName.trim(),
      lastName: values.lastName.trim(),
      role: values.role,
      // '' -> null CLEARS the assignment (back to a standard role); a chosen id sets
      // it, and the server then forces `role` to that custom role's base role.
      customRoleId: values.customRoleId ? values.customRoleId : null,
      isActive: values.isActive,
    };

    try {
      const updated = await updateUser({ id: target.id, patch }).unwrap();
      toast.success(`${fullName(updated)} updated`);
      setTarget(null);
      return true;
    } catch (err) {
      setSubmitError(
        extractApiErrorMessage(err, 'Could not update user. Please try again.'),
      );
      return false;
    }
  };

  return {
    editingUser: target,
    open: target !== null,
    isSaving,
    submitError,
    openEdit: (user: UserRecord) => {
      setSubmitError(null);
      setTarget(user);
    },
    close: () => {
      setSubmitError(null);
      setTarget(null);
    },
    submit,
  };
}
