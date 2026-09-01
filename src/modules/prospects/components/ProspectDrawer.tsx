import { CalendarPlus, MessageSquarePlus } from 'lucide-react';
import { Button, ListboxSelect } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { Pill, StatTile } from '@/shared/ui/data-display';
import { TouchLog } from '@/modules/activity';
import type { AppointmentRecord } from '@/modules/appointments/types/appointmentsTypes';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { NoteRecord } from '@/modules/activity/types/activityTypes';
import type { ReferralSourceRecord } from '@/modules/referrals/types/referralsTypes';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { STAGE_LABELS, URGENCY_LABELS, URGENCY_PILL } from '../constants/prospectsConstants';
import type { ProspectRecord } from '../types/prospectsTypes';

interface ProspectDrawerProps {
  /**
   * Visibility, owned by the caller's explicit state.
   *
   * MUST NOT be derived from `prospect` being present: RTK Query's `data`
   * survives a skip, so a data-derived condition kept this drawer open after
   * Close and made both the × and the Close button look broken.
   */
  open: boolean;
  prospect: ProspectRecord | undefined;
  /** The linked account, when the prospect has one. */
  account: ReferralSourceRecord | undefined;
  notes: readonly NoteRecord[];
  isLoading: boolean;
  isNotesLoading: boolean;
  /** The visit `assignedRep` would be set on. Undefined when there is none yet. */
  appointment: AppointmentRecord | undefined;
  isAppointmentLoading: boolean;
  /** Assignable staff for the nurse/caregiver picker — the same list the
   *  Prospects table's Marketer column uses, from `/users/assignable`. */
  staffOptions: readonly EntitySelectOption[];
  onAssignRep: (userId: string) => void;
  isAssigningRep: boolean;
  onClose: () => void;
  onAddNote: () => void;
  onScheduleVisit: () => void;
}

export function ProspectDrawer({
  open,
  prospect,
  account,
  notes,
  isLoading,
  isNotesLoading,
  appointment,
  isAppointmentLoading,
  staffOptions,
  onAssignRep,
  isAssigningRep,
  onClose,
  onAddNote,
  onScheduleVisit,
}: ProspectDrawerProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      size="lg"
      title={prospect?.patientName ?? 'Prospect'}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button variant="ghost" onClick={onScheduleVisit} disabled={!prospect}>
            <CalendarPlus className="h-4 w-4" /> Schedule visit
          </Button>
          <Button onClick={onAddNote} disabled={!prospect}>
            <MessageSquarePlus className="h-4 w-4" /> Add note
          </Button>
        </>
      }
    >
      {!prospect ? (
        // Open with no record yet is either a fetch in flight or one that
        // failed. Saying which is the difference between "wait a moment" and
        // "close this and try again" — a permanent "Loading…" is a lie.
        <p className="py-6 text-sm text-muted">
          {isLoading
            ? 'Loading prospect…'
            : 'We could not load this prospect. Please close and try again.'}
        </p>
      ) : (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <Pill tone="b">{STAGE_LABELS[prospect.stage]}</Pill>
            {/*
              The urgency field (Hot/Warm/Cold), not the legacy `isHotLead`
              boolean this used to read. `isHotLead` predates `urgency`, no
              form writes it any more (see my-day.service.ts's hotAlerts —
              "the two fields meaning one thing is a product cleanup"), and
              reading it here meant Warm/Cold prospects showed no badge at
              all while the Prospects table's own urgency pill (right next
              to this drawer) disagreed for the same record.
            */}
            <Pill tone={URGENCY_PILL[prospect.urgency]}>
              {URGENCY_LABELS[prospect.urgency]}
            </Pill>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <StatTile
              label="Triage score"
              // Explicitly "Not scored" rather than a dash: this column had zero
              // writers for a long time, and a dash would look like that bug.
              value={
                prospect.aiAdmitScore === null
                  ? 'Not scored'
                  : String(prospect.aiAdmitScore)
              }
              hint="1–10, explainable rubric"
              tone="y"
            />
            <StatTile
              label="Stage entered"
              value={
                prospect.stageEnteredAt
                  ? formatDate(prospect.stageEnteredAt)
                  : '—'
              }
              tone="b"
            />
            <StatTile
              label="Notes"
              value={String(notes.length)}
              tone="g"
            />
          </div>

          <section className="space-y-1.5">
            <h3 className="text-[10px] uppercase tracking-label text-muted-soft">
              Referral
            </h3>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
              <div className="flex gap-2">
                <dt className="text-muted">Facility</dt>
                {/* The LINKED account, not the free-text facilityName. Seeing the
                    real record here is what tells a marketer the referral is
                    joined up rather than a loose string. */}
                <dd className="text-foreground">
                  {account?.name ?? prospect.facilityName ?? '—'}
                  {!prospect.referralSourceId && prospect.facilityName && (
                    <span className="ml-1 text-[11px] text-muted-soft">
                      (not linked)
                    </span>
                  )}
                </dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-muted">Referred by</dt>
                <dd className="text-foreground">
                  {prospect.referringPhysician ?? '—'}
                </dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-muted">Diagnosis</dt>
                <dd className="text-foreground">{prospect.diagnosis ?? '—'}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="text-muted">Phone</dt>
                <dd className="text-foreground">{prospect.phone ?? '—'}</dd>
              </div>
            </dl>
          </section>

          <section className="space-y-1.5">
            <h3 className="text-[10px] uppercase tracking-label text-muted-soft">
              Clinical assignment
            </h3>
            {/* `appointments.assignedRep`, NOT the Marketer column's
                `prospects.assignedTo` (the pipeline owner) — see
                useProspectOwner for why those are two different fields.
                Assigning a nurse or caregiver here is what puts this patient
                on their "My patients" list. */}
            {appointment ? (
              <>
                <ListboxSelect
                  value={appointment.assignedRep ?? ''}
                  options={staffOptions}
                  placeholder="— Unassigned —"
                  disabled={isAssigningRep}
                  onChange={onAssignRep}
                  aria-label={`Assign nurse or caregiver for ${prospect.patientName}`}
                />
                <p className="text-[11px] text-muted-soft">
                  Assigning a nurse or caregiver puts this patient on their
                  &ldquo;My patients&rdquo; list.
                </p>
              </>
            ) : (
              <p className="text-sm text-muted-soft">
                {isAppointmentLoading
                  ? 'Loading visit…'
                  : 'Schedule a visit for this patient to assign a nurse or caregiver.'}
              </p>
            )}
          </section>

          <section className="space-y-1.5">
            <h3 className="text-[10px] uppercase tracking-label text-muted-soft">
              Team notes
            </h3>
            <TouchLog
              notes={notes}
              isLoading={isNotesLoading}
              emptyLabel="No notes on this prospect yet."
            />
          </section>
        </div>
      )}
    </Modal>
  );
}
