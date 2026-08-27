import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
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
    setError,
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
    /**
     * The middle of the three layers on this date (picker floor above,
     * @IsNotPastDate on CreateClRevenueEntryDto below). It exists because the
     * field still accepts a TYPED value the calendar would never have offered,
     * and it turns what was a raw 400 — "entryDate must match
     * /^\d{4}-\d{2}-\d{2}$/ regular expression", shown to the user verbatim —
     * into a sentence under the field.
     *
     * Create only, and on edit only when the date actually CHANGED: an entry
     * whose date has since passed must stay editable, or correcting an amount on
     * last week's row would be blocked by a date nobody touched. Same reason the
     * server-side rule is on the create DTO alone.
     */
    const changedDate = !editing || values.entryDate !== (editing.entryDate ?? '');
    if (changedDate && values.entryDate && values.entryDate < todayLocalDate()) {
      setError('entryDate', { message: 'Entry date cannot be in the past.' });
      return;
    }
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
