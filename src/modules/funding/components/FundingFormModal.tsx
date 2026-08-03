import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { FUNDING_FIELDS } from '../constants/fundingConstants';
import { fundingSchema, type FundingFormValues } from '../schema/fundingSchema';
import { toFundingFormValues } from '../utils/fundingUtils';
import type { FundingRecord } from '../types/fundingTypes';

const EMPTY: FundingFormValues = {
  opportunityName: '',
  sourceUrl: '',
  status: '',
  programType: '',
  maxAwardPerEin: undefined,
  applicationDeadline: '',
  applicationLink: '',
  notes: '',
};

interface FundingFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: FundingRecord | null;
  onClose: () => void;
  onSubmit: (values: FundingFormValues) => Promise<boolean>;
}

export function FundingFormModal({ open, isSaving, editing, onClose, onSubmit }: FundingFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<FundingFormValues>({
    resolver: zodResolver(fundingSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toFundingFormValues(editing) : EMPTY);
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
    <EntityFormModal<FundingFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit opportunity' : 'Add opportunity'}
      submitLabel={editing ? 'Save changes' : 'Save opportunity'}
      fields={FUNDING_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
