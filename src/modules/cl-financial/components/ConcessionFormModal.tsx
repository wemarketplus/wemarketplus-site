import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { CONCESSION_STATUS } from '../constants/clFinancialApiConstants';
import { CONCESSION_FIELDS } from '../constants/clFinancialConstants';
import { concessionSchema, type ConcessionFormValues } from '../schema/clFinancialSchema';
import { toConcessionFormValues } from '../utils/clFinancialMappers';
import type { ClConcessionRecord } from '../types/clFinancialApiTypes';

const EMPTY: ConcessionFormValues = {
  type: '',
  valueAmount: '',
  status: CONCESSION_STATUS.Pending,
  reason: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClConcessionRecord | null;
  onClose: () => void;
  onSubmit: (values: ConcessionFormValues) => Promise<boolean>;
}

export function ConcessionFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<ConcessionFormValues>({
    resolver: zodResolver(concessionSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toConcessionFormValues(editing) : EMPTY);
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
    <EntityFormModal<ConcessionFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit concession' : 'Add concession'}
      submitLabel={editing ? 'Save changes' : 'Add concession'}
      fields={CONCESSION_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
