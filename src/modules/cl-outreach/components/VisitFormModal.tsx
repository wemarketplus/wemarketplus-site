import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { GpsCaptureField } from './GpsCaptureField';
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
  gpsLat: '',
  gpsLng: '',
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
    setValue,
    watch,
    formState: { errors },
  } = useForm<VisitFormValues>({
    resolver: zodResolver(visitSchema),
    defaultValues: EMPTY,
  });

  // Watched rather than read once: the Capture GPS button writes these through
  // setValue, which does not re-render on its own.
  const gpsLat = watch('gpsLat') ?? '';
  const gpsLng = watch('gpsLng') ?? '';

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
      footerNote={
        <GpsCaptureField
          lat={gpsLat}
          lng={gpsLng}
          onCapture={(lat, lng) => {
            setValue('gpsLat', lat, { shouldDirty: true });
            setValue('gpsLng', lng, { shouldDirty: true });
          }}
          onClear={() => {
            setValue('gpsLat', '', { shouldDirty: true });
            setValue('gpsLng', '', { shouldDirty: true });
          }}
        />
      }
    />
  );
}
