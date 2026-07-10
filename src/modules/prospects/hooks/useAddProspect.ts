import { useState } from 'react';
import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useCreateProspectMutation } from '../api/prospectsApi';
import type { NewProspectFormValues } from '../schema/prospectSchema';
import type { CreateProspectRequest } from '../types/prospectsTypes';

// Orchestrates the Add-prospect modal: open/close state plus the real
// POST /prospects mutation. RTK Query invalidates the list tag on success, so
// the new row appears without a manual refetch.
export function useAddProspect() {
  const [open, setOpen] = useState(false);
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
