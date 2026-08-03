import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/modules/auth/utils/errorUtils';
import { useDeleteUserMutation } from '../api/usersApi';
import type { UserRecord } from '../types/usersTypes';
import { fullName } from '../utils/userDisplay';
import { confirm } from '@/shared/ui/feedback';

// Encapsulates the destructive delete flow — confirm, call the mutation, and
// surface success/failure toasts — so components stay free of API + side-effect
// logic.
export function useDeleteUser() {
  const [deleteUserMutation, { isLoading }] = useDeleteUserMutation();

  const deleteUser = async (user: UserRecord) => {
    const ok = await confirm({
      title: `Delete ${fullName(user)}?`,
      body: `${user.email} will lose access immediately.`,
      confirmLabel: 'Delete user',
    });
    if (!ok) return;
    try {
      await deleteUserMutation(user.id).unwrap();
      toast.success(`Deleted ${fullName(user)}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Failed to delete user'));
    }
  };

  return { deleteUser, isDeleting: isLoading };
}
