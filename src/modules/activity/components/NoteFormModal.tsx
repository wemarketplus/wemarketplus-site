import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { EntityFormModal } from '@/shared/ui/entity';
import { Urgency } from '@/shared/types';
import { NOTE_FIELDS } from '../constants/activityConstants';
import { noteSchema, type NoteFormValues } from '../schema/noteSchema';
import { toNoteFormValues } from '../utils/activityMappers';
import type { NoteRecord } from '../types/activityTypes';

const EMPTY: NoteFormValues = {
  prospectId: '',
  summary: '',
  contactType: '',
  urgency: Urgency.Warm,
  patientStatus: '',
  barriers: '',
  nextStep: '',
  followUpDate: '',
};

interface NoteFormModalProps {
  open: boolean;
  isSaving: boolean;
  // When set, the modal is in edit mode and seeds from this record.
  editing?: NoteRecord | null;
  onClose: () => void;
  onSubmit: (values: NoteFormValues) => Promise<boolean>;
}

// Owns the react-hook-form instance for create + edit and delegates rendering to
// the shared EntityFormModal. In edit mode, prospectId is shown but the backend
// ignores it (a note can't be reparented).
export function NoteFormModal({ open, isSaving, editing, onClose, onSubmit }: NoteFormModalProps) {
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors },
  } = useForm<NoteFormValues>({
    resolver: zodResolver(noteSchema),
    defaultValues: EMPTY,
  });

  useEffect(() => {
    if (!open) return;
    reset(editing ? toNoteFormValues(editing) : EMPTY);
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
    <EntityFormModal<NoteFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit note' : 'Add note'}
      submitLabel={editing ? 'Save changes' : 'Save note'}
      fields={NOTE_FIELDS}
      register={register}
      errors={errors}
      onSubmit={submit}
      onClose={close}
    />
  );
}
