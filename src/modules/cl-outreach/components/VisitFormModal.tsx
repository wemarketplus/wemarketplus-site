import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { VISIT_FIELDS } from '../constants/clOutreachConstants';
import { visitSchema, type VisitFormValues } from '../schema/clOutreachSchema';
import { toVisitFormValues } from '../utils/clOutreachMappers';
import type { ClOutreachVisitRecord } from '../types/clOutreachApiTypes';

const EMPTY: VisitFormValues = {
  visitDate: '',
  contactName: '',
  locationName: '',
  visitType: 'in_person',
  miles: '',
  notes: '',
};

interface VisitFormModalProps {
  open: boolean;
  isSaving: boolean;
  editing?: ClOutreachVisitRecord | null;
  onClose: () => void;
  onSubmit: (values: VisitFormValues) => Promise<boolean>;
}

export function VisitFormModal({
  open,
  isSaving,
  editing,
  onClose,
  onSubmit,
}: VisitFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<VisitFormValues>({
    resolver: zodResolver(visitSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toVisitFormValues(editing) : EMPTY);
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
    <EntityFormModal<VisitFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit visit' : 'Log outreach visit'}
      submitLabel={editing ? 'Save changes' : 'Log visit'}
      fields={VISIT_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
