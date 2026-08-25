import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { CL_CARE_LEVEL, CL_URGENCY, FEE_STATUS } from '../constants/clReferralsApiConstants';
import { PAID_REFERRAL_FIELDS } from '../constants/paidReferralsConstants';
import { paidReferralSchema, type PaidReferralFormValues } from '../schema/paidReferralSchema';
import { toPaidReferralFormValues } from '../utils/paidReferralsUtils';
import type { ClPaidReferralRecord } from '../types/clReferralsApiTypes';

const EMPTY: PaidReferralFormValues = {
  prospectName: '',
  prospectPhone: '',
  careLevel: CL_CARE_LEVEL.AssistedLiving,
  urgency: CL_URGENCY.Warm,
  sourceName: '',
  referralFee: '',
  feeStatus: FEE_STATUS.Pending,
  /**
   * BLANK, not 'New Referral'.
   *
   * The stage column is `varchar(100) NOT NULL DEFAULT 'New Referral'`
   * (cl-paid-referral.entity.ts, InitialSchema migration) and
   * CreateClPaidReferralDto marks `stage` @IsOptional — so the server already
   * stamps exactly this value when the field is omitted, and the mapper omits
   * it for a blank (toCreatePaidReferral -> opt('stage', …) drops empty
   * strings). Pre-filling it here duplicated a server default in the client and
   * spent the field's placeholder — the form read as though a stage had been
   * chosen for the user, which is the report.
   *
   * Left OPTIONAL rather than turned into a required picker: the DTO does not
   * require it, and a client-only mandatory rule would invent a constraint the
   * API does not enforce. The `placeholder: 'New Referral'` on the descriptor
   * now shows, which is the honest statement — leave it blank and this is what
   * you get.
   */
  stage: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClPaidReferralRecord | null;
  onClose: () => void;
  onSubmit: (values: PaidReferralFormValues) => Promise<boolean>;
}

export function PaidReferralFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<PaidReferralFormValues>({
    resolver: zodResolver(paidReferralSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toPaidReferralFormValues(editing) : EMPTY);
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
    <EntityFormModal<PaidReferralFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit paid referral' : 'Add paid referral'}
      submitLabel={editing ? 'Save changes' : 'Add referral'}
      fields={PAID_REFERRAL_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
