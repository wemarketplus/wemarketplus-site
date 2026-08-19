import { useState } from 'react';
import { toast } from 'sonner';
import { useAppDispatch } from '@/app/hooks';
// Imported by direct path, NOT via the module barrels: those also export
// ReferralsPage / HospiceContactsPage, which would pull two whole page trees into
// this module and undo the lazy route splitting in router.tsx. Same reason
// useLeadActions reaches for prospectsApi by path.
import { hospiceContactsApi } from '@/modules/hospice-contacts/api/hospiceContactsApi';
import { referralsApi } from '@/modules/referrals/api/referralsApi';
import { REFERRALS_TAGS } from '@/modules/referrals/constants/referralsConstants';
import { confirm } from '@/shared/ui/feedback';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import {
  useCreateProspectMutation,
  useDeleteProspectMutation,
  useUpdateProspectMutation,
} from '../api/prospectsApi';
import { toCreateProspect, toUpdateProspect } from '../utils/prospectsUtils';
import type { NewProspectFormValues } from '../schema/prospectSchema';
import type { ProspectRecord } from '../types/prospectsTypes';

// Orchestrates the Add/Edit-prospect modal and the delete confirm: open/close
// and editing state, plus the real POST/PATCH/DELETE /prospects mutations. RTK
// Query invalidates the list tag on success, so the table reflects the change
// without a manual refetch.
export function useAddProspect() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ProspectRecord | null>(null);
  const dispatch = useAppDispatch();
  const [createProspect, { isLoading: isCreating }] = useCreateProspectMutation();
  const [updateProspect, { isLoading: isUpdating }] = useUpdateProspectMutation();
  const [deleteProspect] = useDeleteProspectMutation();

  // Saving one prospect can also mint a referral source and a hospice contact
  // server-side (ProspectsService.resolveReferralLinks turns the typed
  // Facility / Referring physician into linked records). Those live in other
  // API slices, and createProspect's own `invalidatesTags` cannot reach them.
  //
  // The referral-sources refetch is load-bearing, not cosmetic: the Source
  // column resolves referralSourceId -> name through the cached accounts
  // list, so without this the row the user just created shows a BLANK source
  // until a full page reload. Same reason useLeadActions.convertLead
  // invalidates the prospects list after a conversion.
  const invalidateLinkedRecords = () => {
    dispatch(
      referralsApi.util.invalidateTags([
        { type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' },
      ]),
    );
    dispatch(hospiceContactsApi.util.invalidateTags(['HospiceContact']));
  };

  const submit = async (values: NewProspectFormValues): Promise<boolean> => {
    try {
      if (editing) {
        await updateProspect({ id: editing.id, patch: toUpdateProspect(values) }).unwrap();
        toast.success('Prospect updated');
      } else {
        await createProspect(toCreateProspect(values)).unwrap();
        invalidateLinkedRecords();
        toast.success('Prospect added');
      }
      setOpen(false);
      setEditing(null);
      return true;
    } catch (err) {
      toast.error(
        extractApiErrorMessage(
          err,
          editing ? 'Could not update prospect. Please try again.' : 'Could not add prospect. Please try again.',
        ),
      );
      return false;
    }
  };

  const remove = async (prospect: ProspectRecord): Promise<void> => {
    const label = prospect.pipelineName ?? prospect.patientName;
    const ok = await confirm({
      title: `Delete ${label}?`,
      body: `${label} will be permanently removed from the pipeline.`,
      confirmLabel: 'Delete',
    });
    if (!ok) return;
    try {
      await deleteProspect(prospect.id).unwrap();
      toast.success(`Deleted ${label}`);
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not delete prospect.'));
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
    openEdit: (prospect: ProspectRecord) => {
      setEditing(prospect);
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
