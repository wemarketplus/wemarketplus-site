import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { REFERRAL_FIELDS, REFERRAL_TYPE } from '../constants/clReferralsConstants';
import { referralSchema, type ReferralFormValues } from '../schema/clReferralSchema';
import { toReferralFormValues } from '../utils/clReferralsMappers';
import type { ClReferralSourceRecord } from '../types/clReferralsApiTypes';

const EMPTY: ReferralFormValues = {
  name: '',
  organization: '',
  type: REFERRAL_TYPE.Physician,
  phone: '',
  email: '',
  address: '',
  notes: '',
};

interface ReferralFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: ClReferralSourceRecord | null;
  onClose: () => void;
  onSubmit: (values: ReferralFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function ReferralFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: ReferralFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ReferralFormValues>({
    resolver: zodResolver(referralSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toReferralFormValues(editing) : EMPTY);
  }, [open, editing, reset]);

  const close = () => {
    reset(EMPTY);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    const ok = await onSubmit(values);
    if (ok) reset(EMPTY);
  });

  return (
    <EntityFormModal<ReferralFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit referral source' : 'Add referral source'}
      submitLabel={editing ? 'Save changes' : 'Save source'}
      fields={REFERRAL_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
