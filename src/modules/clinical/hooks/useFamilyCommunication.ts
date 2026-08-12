import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import {
  useCreateNoteMutation,
  useListNotesQuery,
} from '@/modules/activity/api/activityApi';
import { useNoteLookups } from '@/modules/activity/hooks/useNoteLookups';
import type { CreateNoteRequest } from '@/modules/activity/types/activityTypes';
import { FAMILY_CONTACT_ACTIVITY_TYPES } from '@/shared/constants/activityTypeConstants';

/**
 * The Family Communication log: every conversation held with a patient's family,
 * and the one action that adds to it.
 *
 * REUSES THE NOTES MODULE ENTIRELY — no new table, endpoint or form. A family
 * conversation is already exactly a note: it targets a patient and carries the
 * channel in `activityType` (Phone Call / Text · SMS / Facility · Office Visit).
 *
 * WHAT BELONGS IN THIS LOG: a note about a patient, logged on a family channel.
 * That is `activityTypes=FAMILY_CONTACT_ACTIVITY_TYPES` + `hasProspect=true`.
 *
 * It used to be `isFamilySensitive=true`, and that was wrong in the worst
 * direction. `isFamilySensitive` means "team only — never surface this to a family
 * member": it is an exception, it is off by default, and its own help text tells
 * the nurse so. A nurse logging an ordinary call to a daughter correctly left it
 * clear — got a "Family contact logged" toast — and the entry never appeared in
 * the compliance record it was required to appear in. One flag was carrying both
 * "this is a family conversation" and "this is too sensitive to share with the
 * family", which are close to opposite sets. It is now only the latter, and shows
 * as a badge on the row.
 *
 * KNOWN TRADE-OFF, stated rather than hidden: there is no column that says "this
 * note is a family conversation", so the channel stands in for one. A clinical
 * note written from the Notes screen and explicitly tagged Phone Call or
 * Facility / Office Visit will therefore appear here too. In practice that form
 * leaves the type as "Not recorded" (null), which this filter excludes, and a note
 * a clinician did tag as an in-person encounter is defensibly part of the record.
 * If the client wants a hard separation, the right fix is an `isFamilyContact`
 * column set by this screen — a migration, not a filter change.
 *
 * The patient picker comes from `useNoteLookups`, which already resolves the right
 * source per role: the pipeline for marketing roles, and the name-only patient
 * directory for Nurse and Caregiver, who are 403 on the pipeline. That source is
 * tenant-wide ON PURPOSE — see useNoteLookups for why scoping it to the caller's own
 * visits made this compliance log impossible to write for most nurses.
 */
export function useFamilyCommunication() {
  // The whole log, not just this user's: it is a compliance record, and the next
  // clinician to speak to a family needs to know what was already said.
  const { data, isLoading, isError, refetch } = useListNotesQuery({
    activityTypes: FAMILY_CONTACT_ACTIVITY_TYPES.join(','),
    hasProspect: true,
  });
  const [createNote, createState] = useCreateNoteMutation();
  const [patientId, setPatientId] = useState('');
  const [logOpen, setLogOpen] = useState(false);

  const lookups = useNoteLookups(true);
  const patients = lookups.prospectId;
  // id -> patient name, for the log rows. Built from the same option list the
  // picker uses, so a row can never label a patient the current role may not see.
  const patientNames = useMemo(
    () => new Map((patients ?? []).map((o) => [o.value, o.label])),
    [patients],
  );

  const entries = useMemo(
    () =>
      (data?.data ?? []).map((note) => ({
        id: note.id,
        summary: note.summary,
        activityType: note.activityType,
        activityTypeOther: note.activityTypeOther,
        createdAt: note.createdAt,
        // Surfaced as a row badge now that it no longer decides membership: the
        // next clinician to open this log needs to know which entries must not be
        // repeated back to the family.
        isFamilySensitive: note.isFamilySensitive,
        nextStep: note.nextStep,
        // Resolved server-side. Reading it from GET /users here would 403 for the
        // clinical roles this screen exists for, and every row would read as
        // written by nobody.
        author: note.author,
        // Now that the picker is the whole patient directory this is a rare edge:
        // an outreach (facility) row, or a patient soft-deleted since the note was
        // written. The conversation still happened, so the row stays — say so
        // plainly rather than printing a raw uuid or dropping it.
        patientName: note.prospectId
          ? (patientNames.get(note.prospectId) ?? 'Patient no longer on file')
          : '—',
      })),
    [data, patientNames],
  );

  const submit = async (body: CreateNoteRequest): Promise<boolean> => {
    try {
      await createNote(body).unwrap();
      toast.success('Family contact logged');
      return true;
    } catch {
      toast.error('Could not log the family contact');
      return false;
    }
  };

  return {
    entries,
    isLoading,
    isError,
    refetch,
    patients,
    patientId,
    setPatientId,
    logOpen,
    openLog: () => setLogOpen(true),
    closeLog: () => setLogOpen(false),
    isSaving: createState.isLoading,
    submit,
  };
}
