import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { LOC_FIELDS } from '../constants/clFinancialConstants';
import { locSchema, type LocFormValues } from '../schema/clFinancialSchema';
import { toLocFormValues } from '../utils/clFinancialMappers';
import type { ClLocPricingRecord } from '../types/clFinancialApiTypes';

const EMPTY: LocFormValues = {
  level: '',
  label: '',
  description: '',
  addOnRate: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClLocPricingRecord | null;
  onClose: () => void;
  onSubmit: (values: LocFormValues) => Promise<boolean>;
}

export function LocFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<LocFormValues>({
    resolver: zodResolver(locSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toLocFormValues(editing) : EMPTY);
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
    <EntityFormModal<LocFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit care level' : 'Add care level'}
      submitLabel={editing ? 'Save changes' : 'Add level'}
      fields={LOC_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
