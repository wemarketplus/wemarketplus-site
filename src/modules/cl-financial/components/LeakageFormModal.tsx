import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { LEAKAGE_STATUS } from '../constants/clFinancialApiConstants';
import { LEAKAGE_FIELDS } from '../constants/clFinancialConstants';
import { leakageSchema, type LeakageFormValues } from '../schema/clFinancialSchema';
import { toLeakageFormValues } from '../utils/clFinancialMappers';
import type { ClLeakageItemRecord } from '../types/clFinancialApiTypes';

const EMPTY: LeakageFormValues = {
  issue: '',
  type: '',
  monthlyImpact: '',
  status: LEAKAGE_STATUS.Active,
  notes: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClLeakageItemRecord | null;
  onClose: () => void;
  onSubmit: (values: LeakageFormValues) => Promise<boolean>;
}

export function LeakageFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<LeakageFormValues>({
    resolver: zodResolver(leakageSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toLeakageFormValues(editing) : EMPTY);
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
    <EntityFormModal<LeakageFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit leakage item' : 'Add leakage item'}
      submitLabel={editing ? 'Save changes' : 'Add leakage item'}
      fields={LEAKAGE_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
