import { useEffect } from 'react';
import { zodResolver } from '@hookform/resolvers/zod';
import { useForm } from 'react-hook-form';
import { Checkbox, VoiceDictateButton } from '@/shared/ui/core';
import { EntityFormModal } from '@/shared/ui/entity';
import { useNoteFormFields } from '../hooks/useNoteFormFields';
import { useNoteLookups } from '../hooks/useNoteLookups';
import { Urgency } from '@/shared/types';
import { noteSchema, type NoteFormValues } from '../schema/noteSchema';
import { toNoteFormValues } from '../utils/activityMappers';
import type { NoteRecord } from '../types/activityTypes';

const EMPTY: NoteFormValues = {
  prospectId: '',
  referralSourceId: '',
  contactId: '',
  summary: '',
  activityType: '',
  activityTypeOther: '',
  contactType: '',
  urgency: Urgency.Warm,
  patientStatus: '',
  barriers: '',
  nextStep: '',
  followUpDate: '',
  isFamilySensitive: false,
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
    setValue,
    watch,
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

  // Prospect / referral-source / contact pickers. Only fetched while the modal is
  // open, so opening the Notes tab doesn't pull three extra lists nobody asked for.
  const lookups = useNoteLookups(open);
  const { fields, readOnlyValues } = useNoteFormFields(open, watch('prospectId'));

  return (
    <EntityFormModal<NoteFormValues>
      open={open}
      isSaving={isSaving}
      title={editing ? 'Edit note' : 'Add note'}
      submitLabel={editing ? 'Save changes' : 'Save note'}
      fields={fields}
      register={register}
      errors={errors}
      lookups={lookups}
      readOnlyValues={readOnlyValues}
      onSubmit={submit}
      onClose={close}
      // Two controls the field-descriptor grid cannot express — a checkbox with
      // help text and a speech button — so they live in the footerNote slot.
      // (The grid did gain a 'readonly' field type for the clinical role's
      // Referred by / Main contact rows; see useNoteFormFields. A checkbox and a
      // dictation button are still not field descriptors.)
      footerNote={
        <div className="space-y-3">
          {/*
            The family-sensitive classification, which is the whole point of a
            clinician writing here: the guide tells a Nurse to "mark anything
            family-sensitive so it's handled with care by whoever reads it next".
            Without this control the flag existed on the record and on the
            prospect drawer's log, but nothing on this screen could set it.

            The copy is the LogInteractionModal's, word for word, and it is
            load-bearing: isFamilySensitive is a classification, not an access
            control. Wording that implied the note was hidden from teammates
            would get staff writing to it as if it were one.
          */}
          <label className="flex items-start gap-2 text-sm text-foreground">
            <Checkbox className="mt-1" {...register('isFamilySensitive')} />
            <span>
              Team only — not for the family
              <span className="block text-[11px] text-muted-soft">
                Flags the note as family-sensitive. It stays visible to everyone
                on your team; this marks it so it is never surfaced to a family
                member.
              </span>
            </span>
          </label>

          {/* Windshield Voice Mode. Renders nothing on a browser without speech
              recognition (Firefox), instead of a button that does nothing. */}
          <VoiceDictateButton
            baseText={watch('summary') ?? ''}
            onTranscript={(text) =>
              setValue('summary', text, { shouldDirty: true })
            }
          />
        </div>
      }
    />
  );
}
