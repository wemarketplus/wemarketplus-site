import { useState } from 'react';
import { toast } from 'sonner';
import { useCreateInviteMutation } from '@/modules/admin';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useCreateUserMutation } from '../api/usersApi';
import type { NewUserFormValues } from '../schema/usersSchema';
import type { CreateUserRequest, UserRecord } from '../types/usersTypes';
import { fullName } from '../utils/userDisplay';

// Orchestrates the Add-user modal: open/close state, the real POST /users
// mutation, and the optional follow-up POST /invites. RTK Query invalidates
// the users list tag on success, so the new row appears without a manual
// refetch. Create failures (seat limit, duplicate email, permissions) are
// exposed via `submitError` so the modal can show the API message verbatim.
export function useAddUser() {
  const [open, setOpen] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [createUser, { isLoading: isCreating }] = useCreateUserMutation();
  const [createInvite, { isLoading: isInviting }] = useCreateInviteMutation();

  const submit = async (values: NewUserFormValues): Promise<boolean> => {
    setSubmitError(null);

    const body: CreateUserRequest = {
      email: values.email.trim(),
      password: values.password,
      firstName: values.firstName.trim(),
      lastName: values.lastName.trim(),
      role: values.role,
      // Omitted entirely when blank — sending null would CLEAR an assignment, which
      // is meaningless on create and confusing to read in the request log.
      ...(values.customRoleId ? { customRoleId: values.customRoleId } : {}),
    };

    let user: UserRecord;
    try {
      user = await createUser(body).unwrap();
    } catch (err) {
      setSubmitError(extractApiErrorMessage(err, 'Could not add user. Please try again.'));
      return false;
    }

    // Best-effort invite: the account already exists, so a failed invite must
    // not fail the flow — warn and let the admin re-send / relay the password.
    if (values.sendInvite) {
      try {
        await createInvite({ userId: user.id }).unwrap();
      } catch (err) {
        const detail = extractApiErrorMessage(err, '');
        toast.warning(
          detail
            ? `User created, but the invite email failed: ${detail}`
            : 'User created, but the invite email failed.',
        );
      }
    }

    toast.success(`${fullName(user)} added`);
    setOpen(false);
    return true;
  };

  return {
    open,
    isSaving: isCreating || isInviting,
    submitError,
    openModal: () => {
      setSubmitError(null);
      setOpen(true);
    },
    close: () => {
      setSubmitError(null);
      setOpen(false);
    },
    submit,
  };
}
