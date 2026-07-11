import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { HOUSEKEEPING_STATUS } from '../constants/clOperationsApiConstants';
import { HOUSEKEEPING_FIELDS } from '../constants/clOperationsConstants';
import { housekeepingSchema, type HousekeepingFormValues } from '../schema/clOperationsSchema';
import { toHousekeepingFormValues } from '../utils/clOperationsMappers';
import type { ClHousekeepingTaskRecord } from '../types/clOperationsApiTypes';

const EMPTY: HousekeepingFormValues = {
  taskType: '',
  area: '',
  status: HOUSEKEEPING_STATUS.Pending,
  dueDate: '',
};

interface Props {
  open: boolean;
  isSaving: boolean;
  editing?: ClHousekeepingTaskRecord | null;
  onClose: () => void;
  onSubmit: (values: HousekeepingFormValues) => Promise<boolean>;
}

export function HousekeepingFormModal({ open, isSaving, editing, onClose, onSubmit }: Props) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<HousekeepingFormValues>({
    resolver: zodResolver(housekeepingSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toHousekeepingFormValues(editing) : EMPTY);
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
    <EntityFormModal<HousekeepingFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit task' : 'Assign housekeeping task'}
      submitLabel={editing ? 'Save changes' : 'Assign task'}
      fields={HOUSEKEEPING_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
