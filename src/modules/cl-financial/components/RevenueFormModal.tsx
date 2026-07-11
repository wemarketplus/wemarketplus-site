import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { REVENUE_FIELDS } from '../constants/clFinancialConstants';
import { revenueSchema, type RevenueFormValues } from '../schema/clFinancialSchema';
import { toRevenueFormValues } from '../utils/clFinancialMappers';
import type { ClRevenueEntryRecord } from '../types/clFinancialApiTypes';

const EMPTY: RevenueFormValues = {
  entryDate: '',
  category: 'rent',
  amount: '',
  budgetAmount: '',
  description: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClRevenueEntryRecord | null;
  onClose: () => void;
  onSubmit: (values: RevenueFormValues) => Promise<boolean>;
}

export function RevenueFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<RevenueFormValues>({
    resolver: zodResolver(revenueSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toRevenueFormValues(editing) : EMPTY);
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
    <EntityFormModal<RevenueFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit entry' : 'Add ledger entry'}
      submitLabel={editing ? 'Save changes' : 'Add entry'}
      fields={REVENUE_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
