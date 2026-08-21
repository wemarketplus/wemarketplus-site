import { useMemo, useState } from 'react';
import { Plus } from 'lucide-react';
import { Button, Card, CardContent, Checkbox, Label, Select } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { useRole, HL_FIELD_ROLES } from '@/shared/rbac';
import {
  URGENCY_LABELS,
  URGENCY_TONE,
} from '@/shared/constants/urgencyConstants';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { useNotePatientOptions } from '../hooks/useNoteLookups';
import { useProspectNotes } from '../hooks/useProspectNotes';
import { activityTypeLabel } from '../utils/activityUtils';
import { NoteFormModal } from './NoteFormModal';
import { TeamOnlyPill } from './TeamOnlyPill';
import type { ListNotesQuery } from '../types/activityTypes';

/**
 * Notes & team notes — the team-visible record of what happened with a patient.
 *
 * This is the ONLY route to team notes for a clinician. The equivalent list inside
 * the prospect drawer sits behind the Prospects module, which is HL_MARKETING_ROLES
 * only, so a Nurse or Caregiver could never reach it — while both product guides
 * send them here to "document clinical context" and "jot down anything the team
 * should know". Hence the three things this screen must do rather than merely list
 * rows: filter to one patient, show the family-sensitive classification, and let
 * the author set it (NoteFormModal).
 */
export function NotesList() {
  /**
   * Both filters are SERVER-side (QueryNotesDto), because the list is tenant-wide:
   * every note every marketer wrote is in it. Narrowing in the component would
   * mean paging through all of them to find one patient's clinical history.
   */
  const [patientId, setPatientId] = useState('');
  const [teamOnly, setTeamOnly] = useState(false);

  // Role-aware: the pipeline for marketing, the user's own scheduled patients for
  // a clinician — the same split the note form's picker uses, so a nurse can only
  // filter by patients they are actually involved with.
  const patientOptions = useNotePatientOptions(true);

  const filters = useMemo<ListNotesQuery>(
    () => ({
      ...(patientId ? { prospectId: patientId } : {}),
      // Sent only when ON. `isFamilySensitive=false` is a real filter server-side
      // (everything that is NOT marked), which is not what "no filter" means.
      ...(teamOnly ? { isFamilySensitive: true } : {}),
    }),
    [patientId, teamOnly],
  );

  const { notes, records, crud, submit } = useProspectNotes(filters);

  /**
   * Who may WRITE a note: every field persona, not just management.
   *
   * This was `STAFF_ROLES`, which left Nurse and Caregiver with a read-only list —
   * they could see the team's notes and add nothing. Both product guides instruct
   * them to write here ("document clinical context", "jot down anything the team
   * should know"), so the restriction contradicted the product.
   *
   * It was also client-only: POST/PATCH /notes carries no @Roles at all, so the
   * API always accepted these authors. Hiding the button did not protect anything
   * — it just hid the feature from the two roles that need it most.
   */
  const { isAny } = useRole();
  const canEdit = isAny(HL_FIELD_ROLES);

  const modal = canEdit ? (
    <NoteFormModal
      open={crud.createOpen || crud.editing !== null}
      isSaving={crud.isSaving}
      editing={crud.editing}
      onClose={crud.editing ? crud.closeEdit : crud.closeCreate}
      onSubmit={submit}
    />
  ) : null;

  const isFiltered = Boolean(patientId) || teamOnly;

  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="flex flex-wrap items-end gap-4 px-6 py-4">
          <div className="min-w-[220px] flex-1">
            <Label htmlFor="notes-patient">Patient</Label>
            <Select
              id="notes-patient"
              value={patientId}
              onChange={(e) => setPatientId(e.target.value)}
              // Undefined means the list is still loading (useLookupOptions), so
              // an empty picker is never mistaken for "no patients".
              disabled={!patientOptions}
            >
              <option value="">
                {patientOptions ? 'All patients' : 'Loading…'}
              </option>
              {(patientOptions ?? []).map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </div>

          {/* Worded as a view ("show only…"), not as the classification itself —
              a filter that read "Team only — not for the family" would look like
              the control that SETS the flag, which lives on the note form. */}
          <label className="flex items-center gap-2 py-2.5 text-sm text-foreground">
            <Checkbox
              checked={teamOnly}
              onChange={(e) => setTeamOnly(e.target.checked)}
            />
            Show only “Team only” notes
          </label>

          {canEdit && (
            <Button size="sm" className="ml-auto" onClick={crud.openCreate}>
              <Plus className="h-4 w-4" />
              Add note
            </Button>
          )}
        </CardContent>
      </Card>

      {/*
        Said once, plainly, on the surface where the flag is both read and written.
        isFamilySensitive is a classification, NOT an access control — everyone on
        the team reads the note either way. Leaving that implicit is the dangerous
        option: staff who read the badge as a permission would put things here
        expecting it to keep them from a colleague.
      */}
      <p className="px-1 text-xs text-muted-soft">
        Every note here is visible to your whole team. “Team only” does not hide a
        note from teammates — it marks content that must never be surfaced to a
        family member.
      </p>

      {notes.length === 0 ? (
        <Card>
          <CardContent className="p-10 text-center text-sm text-muted">
            {isFiltered
              ? 'No notes match this filter.'
              : 'No structured notes recorded yet.'}
          </CardContent>
        </Card>
      ) : (
        notes.map((n, i) => {
          // `notes` is `records.map(toProspectNote)`, so the index pairs the
          // view-model with the record it came from. The record is what carries
          // the fields the legacy ProspectNote shape has no room for
          // (isFamilySensitive, activityType) and what the edit form seeds from.
          const record = records[i];
          const type = record ? activityTypeLabel(record) : '';
          return (
            <Card key={n.id}>
              <CardContent className="space-y-3 px-6 py-5">
                <header className="flex items-center justify-between gap-3">
                  <div>
                    {/* `position` is not on the note read model, so it is '' for
                        every row today — rendering the separator unconditionally
                        printed a trailing "·" after each author's name. */}
                    <p className="text-sm font-semibold text-foreground">
                      {n.author || 'Unknown author'}
                      {n.position && (
                        <span className="ml-1 text-muted-soft">
                          · {n.position}
                        </span>
                      )}
                    </p>
                    {/* `contactType` is the pre-`activityType` free-text field and
                        is null on everything written since, so showing it alone
                        left a bare separator on every recent note. */}
                    <p className="text-xs text-muted-soft">
                      {type || n.contactType || 'Interaction not recorded'}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {record?.isFamilySensitive && <TeamOnlyPill />}
                    <Pill tone="none" className={URGENCY_TONE[n.urgency]}>
                      {URGENCY_LABELS[n.urgency]}
                    </Pill>
                    {canEdit && (
                      <EntityRowActions
                        onEdit={() => {
                          if (record) crud.openEdit(record);
                        }}
                      />
                    )}
                  </div>
                </header>
                <p className="text-sm text-foreground">{n.summary}</p>
                {n.patientStatus && (
                  <p className="text-xs text-muted">
                    <span className="font-semibold text-muted-soft">
                      Status:{' '}
                    </span>
                    {n.patientStatus}
                  </p>
                )}
                {n.barriers && (
                  <p className="text-xs text-muted">
                    <span className="font-semibold text-muted-soft">
                      Barriers:{' '}
                    </span>
                    {n.barriers}
                  </p>
                )}
                <p className="text-xs text-primary">
                  <span className="font-semibold">Next step: </span>
                  {n.nextStep}
                </p>
                <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                  {formatDateTime(n.date)} · {n.assignedTo}
                </p>
              </CardContent>
            </Card>
          );
        })
      )}

      {modal}
    </div>
  );
}
