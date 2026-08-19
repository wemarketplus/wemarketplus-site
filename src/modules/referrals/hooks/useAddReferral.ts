import { useState } from 'react';
import { toast } from 'sonner';
import { confirm } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useCreateReferralMutation,
  useDeleteReferralMutation,
  useUpdateReferralMutation,
} from '../api/referralsApi';
import { toCreateReferral, toUpdateReferral } from '../utils/referralsUtils';
import type { NewReferralFormValues } from '../schema/referralSchema';
import type { ReferralSourceRecord } from '../types/referralsTypes';

// Orchestrates the Add/Edit-referral-source modal and the delete confirm:
// open/close and editing state, plus the real POST/PATCH/DELETE
// /referral-sources mutations (list tag invalidation refreshes the table).
export function useAddReferral() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ReferralSourceRecord | null>(null);
  const [createReferral, { isLoading: isCreating }] = useCreateReferralMutation();
  const [updateReferral, { isLoading: isUpdating }] = useUpdateReferralMutation();
  const [deleteReferral] = useDeleteReferralMutation();

  const submit = async (values: NewReferralFormValues): Promise<boolean> => {
    try {
      if (editing) {
        await updateReferral({ id: editing.id, patch: toUpdateReferral(values) }).unwrap();
        toast.success('Referral source updated');
      } else {
        await createReferral(toCreateReferral(values)).unwrap();
        toast.success('Referral source added');
      }
      setOpen(false);
      setEditing(null);
      return true;
    } catch (err) {
      toast.error(
        extractApiErrorMessage(
          err,
          editing
            ? 'Could not update referral source. Please try again.'
            : 'Could not add referral source. Please try again.',
        ),
      );
      return false;
    }
  };

  const remove = async (source: ReferralSourceRecord): Promise<void> => {
    const ok = await confirm({
      title: `Delete ${source.name}?`,
      body: `${source.name} will be permanently removed.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    try {
      await deleteReferral(source.id).unwrap();
      toast.success(`Deleted ${source.name}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not delete referral source.'));
    }
  };

  return {
    open,
    editing,
    isSaving: editing ? isUpdating : isCreating,
    openModal: () => {
      setEditing(null);
      setOpen(true);
    },
    openEdit: (source: ReferralSourceRecord) => {
      setEditing(source);
      setOpen(true);
    },
    close: () => {
      setOpen(false);
      setEditing(null);
    },
    submit,
    remove,
  };
}
