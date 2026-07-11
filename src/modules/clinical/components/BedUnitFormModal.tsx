import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { BED_UNIT_STATUS } from '../constants/clinicalStatus';
import { BED_UNIT_FIELDS } from '../constants/clinicalTableConstants';
import { bedUnitSchema, type BedUnitFormValues } from '../schema/bedUnitSchema';
import { toBedUnitFormValues } from '../utils/bedUnitUtils';
import type { BedUnitRecord } from '../types/clinicalApiTypes';

const EMPTY: BedUnitFormValues = {
  facilityName: '',
  bedType: '',
  status: BED_UNIT_STATUS.Available,
  patientName: '',
  notes: '',
};

interface BedUnitFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: BedUnitRecord | null;
  onClose: () => void;
  onSubmit: (values: BedUnitFormValues) => Promise<boolean>;
}

export function BedUnitFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: BedUnitFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<BedUnitFormValues>({
    resolver: zodResolver(bedUnitSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toBedUnitFormValues(editing) : EMPTY);
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
    <EntityFormModal<BedUnitFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit bed unit' : 'Add bed unit'}
      submitLabel={editing ? 'Save changes' : 'Save unit'}
      fields={BED_UNIT_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
