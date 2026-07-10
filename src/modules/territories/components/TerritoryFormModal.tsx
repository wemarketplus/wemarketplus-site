import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { TERRITORY_FIELDS } from '../constants/territoriesConstants';
import { territorySchema, type TerritoryFormValues } from '../schema/territorySchema';
import { toTerritoryFormValues } from '../utils/territoriesUtils';
import type { TerritoryRecord } from '../types/territoriesTypes';

const EMPTY: TerritoryFormValues = {
  name: '',
  city: '',
  state: '',
  zipCodes: '',
  assignedTo: '',
  priority: '',
  notes: '',
};

interface TerritoryFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: TerritoryRecord | null;
  onClose: () => void;
  onSubmit: (values: TerritoryFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function TerritoryFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: TerritoryFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TerritoryFormValues>({
    resolver: zodResolver(territorySchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toTerritoryFormValues(editing) : EMPTY);
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
    <EntityFormModal<TerritoryFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit territory' : 'Add territory'}
      submitLabel={editing ? 'Save changes' : 'Save territory'}
      fields={TERRITORY_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
