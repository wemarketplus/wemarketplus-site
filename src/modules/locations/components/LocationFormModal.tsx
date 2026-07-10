import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { LOCATION_FIELDS } from '../constants/locationsConstants';
import { locationSchema, type LocationFormValues } from '../schema/locationSchema';
import { toLocationFormValues } from '../utils/locationsUtils';
import type { LocationRecord } from '../types/locationsTypes';

const EMPTY: LocationFormValues = {
  locationName: '',
  status: '',
  employeeCount: undefined,
  city: '',
  county: '',
  state: '',
  address: '',
  companyId: '',
  wibId: '',
  notes: '',
};

interface LocationFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: LocationRecord | null;
  onClose: () => void;
  onSubmit: (values: LocationFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. Resets from the edited record when it changes.
export function LocationFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: LocationFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<LocationFormValues>({
    resolver: zodResolver(locationSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toLocationFormValues(editing) : EMPTY);
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
    <EntityFormModal<LocationFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit location' : 'Add location'}
      submitLabel={editing ? 'Save changes' : 'Save location'}
      fields={LOCATION_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
