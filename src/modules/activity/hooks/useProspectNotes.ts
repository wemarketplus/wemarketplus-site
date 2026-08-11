import { useMemo } from 'react';
import { useUserNames } from '@/shared/hooks';
import type { ProspectNote } from '@/shared/types';
import { useEntityCrud } from '@/shared/ui/entity';
import {
  useCreateNoteMutation,
  useListNotesQuery,
  useUpdateNoteMutation,
} from '../api/activityApi';
import { toProspectNote, toCreateNote, toUpdateNote } from '../utils/activityMappers';
import type { NoteFormValues } from '../schema/noteSchema';
import type { ListNotesQuery, NoteRecord } from '../types/activityTypes';

// The backend exposes no DELETE for notes; this no-op keeps the shared
// useEntityCrud contract satisfied so the notes view never renders a delete
// action it can't fulfil.
const noRemove = () => ({ unwrap: async () => undefined });

/**
 * The team notes list plus its create/edit flow.
 *
 * `filters` goes straight to GET /notes, so it may only carry what QueryNotesDto
 * actually accepts (prospectId / referralSourceId / contactId / isFamilySensitive
 * / pagination). Filtering server-side rather than in the component matters here:
 * the list is tenant-wide, so a clinician looking for one patient's notes would
 * otherwise have to page through every note the marketing team ever wrote.
 */
export function useProspectNotes(filters?: ListNotesQuery) {
  const { data } = useListNotesQuery(filters ?? undefined);

  // Keep the raw records around so edit can seed from the full note (the
  // ProspectNote view-model drops fields the form needs, e.g. prospectId).
  const records = useMemo<readonly NoteRecord[]>(() => data?.data ?? [], [data]);

  // A note stores only `createdBy` (a user id). Without this table the card
  // header rendered that uuid where the author's name belongs.
  const userNames = useUserNames();

  const notes = useMemo<readonly ProspectNote[]>(
    () => records.map((r) => toProspectNote(r, userNames)),
    [records, userNames],
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
