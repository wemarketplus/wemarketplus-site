import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { TRAINING_PROVIDER_FIELDS } from '../constants/trainingConstants';
import {
  trainingProviderSchema,
  type TrainingProviderFormValues,
} from '../schema/trainingProviderSchema';
import { toTrainingProviderFormValues } from '../utils/trainingProvidersUtils';
import type { TrainingProviderRecord } from '../types/trainingTypes';

const EMPTY: TrainingProviderFormValues = {
  name: '',
  providerType: '',
  website: '',
  contactEmail: '',
  contactPhone: '',
  programs: '',
  state: '',
  status: '',
  notes: '',
};

interface TrainingProviderFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: TrainingProviderRecord | null;
  onClose: () => void;
  onSubmit: (values: TrainingProviderFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function TrainingProviderFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: TrainingProviderFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TrainingProviderFormValues>({
    resolver: zodResolver(trainingProviderSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toTrainingProviderFormValues(editing) : EMPTY);
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
    <EntityFormModal<TrainingProviderFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit training provider' : 'Add training provider'}
      submitLabel={editing ? 'Save changes' : 'Save provider'}
      fields={TRAINING_PROVIDER_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
