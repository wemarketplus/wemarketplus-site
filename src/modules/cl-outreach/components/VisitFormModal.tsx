import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { todayLocalDate } from '@/shared/utils/dateFormatter';
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
    setError,
    setValue,
    watch,
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
    /**
     * The middle of the three layers on this date (picker floor in VISIT_FIELDS,
     * @IsNotPastDate on CreateClOutreachVisitDto). It exists because the field
     * still accepts a TYPED value the calendar would never have offered, and it
     * turns what was a raw 400 — "visitDate must match
     * /^\d{4}-\d{2}-\d{2}$/ regular expression", shown to the user verbatim —
     * into a sentence under the field.
     *
     * Create only, and on edit only when the date actually CHANGED: a visit
     * logged last week must stay editable — adding notes or miles to it must not
     * be blocked by its own date. Same reason the server-side rule is on the
     * create DTO alone.
     */
    const changedDate = !editing || values.visitDate !== (editing.visitDate ?? '');
    if (changedDate && values.visitDate && values.visitDate < todayLocalDate()) {
      setError('visitDate', { message: 'Visit date cannot be in the past.' });
      return;
    }
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
      // `watch`/`setValue` are what the Location field needs to read and write
      // the visit's name and its gpsLat/gpsLng together.
      watch={watch}
      setValue={setValue}
    />
  );
}
