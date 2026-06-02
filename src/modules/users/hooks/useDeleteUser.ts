import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useDeleteUserMutation } from '../api/usersApi';
import type { UserRecord } from '../types/usersTypes';
import { fullName } from '../utils/userDisplay';

// Encapsulates the destructive delete flow — confirm, call the mutation, and
// surface success/failure toasts — so components stay free of API + side-effect
// logic.
export function useDeleteUser() {
  const [deleteUserMutation, { isLoading }] = useDeleteUserMutation();

  const deleteUser = async (user: UserRecord) => {
    if (!window.confirm(`Delete ${fullName(user)}? This cannot be undone.`)) return;
    try {
      await deleteUserMutation(user.id).unwrap();
      toast.success(`Deleted ${fullName(user)}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Failed to delete user'));
    }
  };

  return { deleteUser, isDeleting: isLoading };
}
