import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { GOAL_FIELDS } from '../constants/activityConstants';
import { goalSchema, type GoalFormValues } from '../schema/goalSchema';
import { toGoalFormValues } from '../utils/activityMappers';
import type { GoalRecord } from '../types/activityTypes';

const EMPTY: GoalFormValues = {
  title: '',
  targetValue: 0,
  currentValue: 0,
  unit: '',
  period: 'daily',
};

interface GoalFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: GoalRecord | null;
  onClose: () => void;
  onSubmit: (values: GoalFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal.
export function GoalFormModal({ open, isSaving, editing, onClose, onSubmit }: GoalFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<GoalFormValues>({
    resolver: zodResolver(goalSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toGoalFormValues(editing) : EMPTY);
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
    <EntityFormModal<GoalFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit goal' : 'Add goal'}
      submitLabel={editing ? 'Save changes' : 'Save goal'}
      fields={GOAL_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
