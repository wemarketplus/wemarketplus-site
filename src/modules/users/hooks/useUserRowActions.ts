import { useState } from 'react';
import { toast } from 'sonner';
import { useCreateInviteMutation } from '@/modules/admin';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useAdminResetPasswordMutation, useUpdateUserMutation } from '../api/usersApi';
import type { UserRecord } from '../types/usersTypes';
import { fullName } from '../utils/userDisplay';
import { confirm } from '@/shared/ui/feedback';

// One-time reveal of an admin-generated temporary password. The backend only
// returns it once (it is hashed on store), so the UI must surface it until the
// admin dismisses the dialog.
export interface TempPasswordReveal {
  user: UserRecord;
  temporaryPassword: string;
}

// Consolidates the non-editing row actions: admin password reset (with a
// one-time reveal dialog), resend invite (re-issues an invite token + email via
// POST /invites), and deactivate/reactivate (toggle isActive via PATCH). Each
// surfaces the backend message verbatim on failure and a success toast, and the
// mutations invalidate the Users tags so the list stays in sync.
export function useUserRowActions() {
  const [reveal, setReveal] = useState<TempPasswordReveal | null>(null);
  const [resetPassword, { isLoading: isResetting }] = useAdminResetPasswordMutation();
  const [createInvite, { isLoading: isInviting }] = useCreateInviteMutation();
  const [updateUser, { isLoading: isTogglingActive }] = useUpdateUserMutation();

  const resetUserPassword = async (user: UserRecord) => {
    const ok = await confirm({
      title: `Reset ${fullName(user)}'s password?`,
      body: 'They will be shown a temporary password and forced to set a new one on next login.',
      confirmLabel: 'Reset password',
    });
    if (!ok) return;
    try {
      const { temporaryPassword } = await resetPassword(user.id).unwrap();
      setReveal({ user, temporaryPassword });
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Failed to reset password'));
    }
  };

  const resendInvite = async (user: UserRecord) => {
    try {
      await createInvite({ userId: user.id }).unwrap();
      toast.success(`Invite re-sent to ${user.email}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Failed to resend invite'));
    }
  };

  const setUserActive = async (user: UserRecord, isActive: boolean) => {
    const verb = isActive ? 'Reactivate' : 'Deactivate';
    const ok = await confirm({
      title: `${verb} ${fullName(user)}?`,
      body: isActive
        ? `${user.email} regains access immediately.`
        : `${user.email} loses access immediately. Their records are kept.`,
      confirmLabel: verb,
      // Reversible either way — this is a state change, not a deletion.
      destructive: !isActive,
    });
    if (!ok) return;
    try {
      await updateUser({ id: user.id, patch: { isActive } }).unwrap();
      toast.success(`${fullName(user)} ${isActive ? 'reactivated' : 'deactivated'}`);
    } catch (err) {
      // Surfaces last-privileged / can't-disable-self messages verbatim.
      toast.error(extractApiErrorMessage(err, `Failed to ${verb.toLowerCase()} user`));
    }
  };

  return {
    reveal,
    dismissReveal: () => setReveal(null),
    resetUserPassword,
    resendInvite,
    setUserActive,
    isBusy: isResetting || isInviting || isTogglingActive,
  };
}
