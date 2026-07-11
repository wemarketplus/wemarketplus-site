import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { TELEHEALTH_STATUS } from '../constants/clinicalStatus';
import { TELEHEALTH_FIELDS } from '../constants/clinicalTableConstants';
import { telehealthSchema, type TelehealthFormValues } from '../schema/telehealthSchema';
import { toTelehealthFormValues } from '../utils/telehealthUtils';
import type { TelehealthSessionRecord } from '../types/clinicalApiTypes';

const EMPTY: TelehealthFormValues = {
  patientName: '',
  providerName: '',
  sessionType: '',
  scheduledAt: '',
  durationMin: '',
  status: TELEHEALTH_STATUS.Scheduled,
  notes: '',
};

interface TelehealthFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: TelehealthSessionRecord | null;
  onClose: () => void;
  onSubmit: (values: TelehealthFormValues) => Promise<boolean>;
}

export function TelehealthFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: TelehealthFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<TelehealthFormValues>({
    resolver: zodResolver(telehealthSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toTelehealthFormValues(editing) : EMPTY);
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
    <EntityFormModal<TelehealthFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit session' : 'Schedule session'}
      submitLabel={editing ? 'Save changes' : 'Save session'}
      fields={TELEHEALTH_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
