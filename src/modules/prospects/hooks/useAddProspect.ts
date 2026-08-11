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
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useCreateProspectMutation } from '../api/prospectsApi';
import type { NewProspectFormValues } from '../schema/prospectSchema';
import type { CreateProspectRequest } from '../types/prospectsTypes';

// Orchestrates the Add-prospect modal: open/close state plus the real
// POST /prospects mutation. RTK Query invalidates the list tag on success, so
// the new row appears without a manual refetch.
export function useAddProspect() {
  const [open, setOpen] = useState(false);
  const dispatch = useAppDispatch();
  const [createProspect, { isLoading }] = useCreateProspectMutation();

  const submit = async (values: NewProspectFormValues): Promise<boolean> => {
    // Drop blank optionals so we never send empty strings the DTO would reject.
    const body: CreateProspectRequest = {
      patientName: values.patientName.trim(),
      stage: values.stage,
      urgency: values.urgency,
      ...(values.facilityName?.trim() ? { facilityName: values.facilityName.trim() } : {}),
      ...(values.referringPhysician?.trim()
        ? { referringPhysician: values.referringPhysician.trim() }
        : {}),
      ...(values.diagnosis?.trim() ? { diagnosis: values.diagnosis.trim() } : {}),
      ...(values.phone?.trim() ? { phone: values.phone.trim() } : {}),
      ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
    };

    try {
      await createProspect(body).unwrap();
      /**
       * Saving one prospect can also mint a referral source and a hospice contact
       * server-side (ProspectsService.resolveReferralLinks turns the typed
       * Facility / Referring physician into linked records). Those live in other
       * API slices, and createProspect's own `invalidatesTags` cannot reach them.
       *
       * The referral-sources refetch is load-bearing, not cosmetic: the Source
       * column resolves referralSourceId -> name through the cached accounts
       * list, so without this the row the user just created shows a BLANK source
       * until a full page reload. Same reason useLeadActions.convertLead
       * invalidates the prospects list after a conversion.
       */
      dispatch(
        referralsApi.util.invalidateTags([
          { type: REFERRALS_TAGS.List, id: 'PARTIAL-LIST' },
        ]),
      );
      dispatch(hospiceContactsApi.util.invalidateTags(['HospiceContact']));
      toast.success('Prospect added');
      setOpen(false);
      return true;
    } catch (err) {
      toast.error(extractApiErrorMessage(err, 'Could not add prospect. Please try again.'));
      return false;
    }
  };

  return {
    open,
    isSaving: isLoading,
    openModal: () => setOpen(true),
    close: () => setOpen(false),
    submit,
  };
}
