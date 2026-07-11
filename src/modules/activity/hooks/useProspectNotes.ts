import { useMemo } from 'react';
import type { ProspectNote } from '@/shared/types';
import { useEntityCrud } from '@/shared/ui/entity';
import {
  useCreateNoteMutation,
  useListNotesQuery,
  useUpdateNoteMutation,
} from '../api/activityApi';
import { toProspectNote, toCreateNote, toUpdateNote } from '../utils/activityMappers';
import type { NoteFormValues } from '../schema/noteSchema';
import type { NoteRecord } from '../types/activityTypes';

// The backend exposes no DELETE for notes; this no-op keeps the shared
// useEntityCrud contract satisfied so the notes view never renders a delete
// action it can't fulfil.
const noRemove = () => ({ unwrap: async () => undefined });

export function useProspectNotes() {
  const { data } = useListNotesQuery();

  // Keep the raw records around so edit can seed from the full note (the
  // ProspectNote view-model drops fields the form needs, e.g. prospectId).
  const records = useMemo<readonly NoteRecord[]>(() => data?.data ?? [], [data]);
  const notes = useMemo<readonly ProspectNote[]>(
    () => records.map(toProspectNote),
    [records],
  );

  const [createNote, createState] = useCreateNoteMutation();
  const [updateNote, updateState] = useUpdateNoteMutation();

  const crud = useEntityCrud<
    NoteRecord,
    ReturnType<typeof toCreateNote>,
    ReturnType<typeof toUpdateNote>
  >({
    noun: 'note',
    create: createNote,
    update: updateNote,
    remove: noRemove,
    isSaving: createState.isLoading || updateState.isLoading,
    labelOf: (n) => n.summary.slice(0, 40) || 'note',
  });

  const submit = (values: NoteFormValues) =>
    crud.editing
      ? crud.submitUpdate(crud.editing.id, toUpdateNote(values))
      : crud.submitCreate(toCreateNote(values));

  return { notes, records, crud, submit, isUsingFixture: false };
}
