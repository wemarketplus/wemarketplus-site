import { useState } from 'react';
import { toast } from 'sonner';
import { useCreateReferralMutation } from '../api/referralsApi';
import type { NewReferralFormValues } from '../schema/referralSchema';
import type { CreateReferralSourceRequest } from '../types/referralsTypes';

// Orchestrates the Add-referral-source modal: open/close state plus the real
// POST /referral-sources mutation (list tag invalidation refreshes the table).
export function useAddReferral() {
  const [open, setOpen] = useState(false);
  const [createReferral, { isLoading }] = useCreateReferralMutation();

  const submit = async (values: NewReferralFormValues): Promise<boolean> => {
    const body: CreateReferralSourceRequest = {
      name: values.name.trim(),
      type: values.type,
      ...(values.contactName?.trim() ? { contactName: values.contactName.trim() } : {}),
      ...(values.phone?.trim() ? { phone: values.phone.trim() } : {}),
      ...(values.email?.trim() ? { email: values.email.trim() } : {}),
      ...(values.city?.trim() ? { city: values.city.trim() } : {}),
      ...(values.state?.trim() ? { state: values.state.trim() } : {}),
      ...(values.notes?.trim() ? { notes: values.notes.trim() } : {}),
    };

    try {
      await createReferral(body).unwrap();
      toast.success('Referral source added');
      setOpen(false);
      return true;
    } catch {
      toast.error('Could not add referral source. Please try again.');
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
