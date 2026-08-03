import { useState } from 'react';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { JOB_TYPE_OPTIONS } from '@/modules/jobs/constants/jobsConstants';
import type { JobType } from '@/modules/jobs/types/jobsTypes';
import {
  ACTIVITY_TYPE_OPTIONS,
  ACTIVITY_TYPE_REQUIRING_DETAIL,
  type ActivityType,
} from '@/shared/constants/activityTypeConstants';
import { APPOINTMENT_OUTCOME_OPTIONS } from '../constants/appointmentsConstants';
import {
  AppointmentOutcome,
  type AppointmentRecord,
  type CompleteAppointmentRequest,
} from '../types/appointmentsTypes';

interface CompleteAppointmentModalProps {
  appointment: AppointmentRecord | null;
  isSaving: boolean;
  onClose: () => void;
  onSubmit: (id: string, body: CompleteAppointmentRequest) => void;
}

/**
 * Logs the visit outcome.
 *
 * Three things happen here, and they are deliberately distinct:
 *   * `activityType` records WHAT the visit was — one enum shared with notes, so a
 *     five-minute brochure drop-off is distinguishable from a two-hour
 *     lunch-and-learn (previously both were just `in_person`).
 *   * `nextSteps` records what was PROMISED, and a due date auto-creates a
 *     Reminder for the rep. Nobody, including the marketer two weeks later, could
 *     previously tell what was committed to.
 *   * `nextJob*` chains the next piece of FIELD WORK. A promise to post a brochure
 *     is not an assessment visit, so these are separate fields, not one.
 *
 * A `follow_up_needed` outcome chains the follow-up job automatically; the note
 * below keeps that automation visible rather than surprising.
 */
export function CompleteAppointmentModal({
  appointment,
  isSaving,
  onClose,
  onSubmit,
}: CompleteAppointmentModalProps) {
  const [outcome, setOutcome] = useState<AppointmentOutcome>(
    AppointmentOutcome.Positive,
  );
  const [visitNotes, setVisitNotes] = useState('');
  const [activityType, setActivityType] = useState<ActivityType | ''>('');
  const [activityTypeOther, setActivityTypeOther] = useState('');
  const [nextSteps, setNextSteps] = useState('');
  const [nextStepsDueDate, setNextStepsDueDate] = useState('');
  const [touched, setTouched] = useState(false);
  const [nextJobType, setNextJobType] = useState<JobType | ''>('');
  const [nextJobObjective, setNextJobObjective] = useState('');
  const [nextJobDueDate, setNextJobDueDate] = useState('');

  const willChain =
    outcome === AppointmentOutcome.FollowUpNeeded ||
    nextJobType !== '' ||
    nextJobObjective.trim() !== '' ||
    nextJobDueDate !== '';

  // Mirrors the backend rule so the user is told before the round trip.
  const needsActivityDetail = activityType === ACTIVITY_TYPE_REQUIRING_DETAIL;
  const missingActivityDetail =
    needsActivityDetail && activityTypeOther.trim() === '';

  const submit = () => {
    if (!appointment) return;
    setTouched(true);
    if (missingActivityDetail) return;
    onSubmit(appointment.id, {
      outcome,
      visitNotes: visitNotes.trim() || undefined,
      activityType: activityType || undefined,
      activityTypeOther: needsActivityDetail
        ? activityTypeOther.trim()
        : undefined,
      nextSteps: nextSteps.trim() || undefined,
      nextStepsDueDate: nextStepsDueDate || undefined,
      nextJobType: nextJobType || undefined,
      nextJobObjective: nextJobObjective.trim() || undefined,
      nextJobDueDate: nextJobDueDate || undefined,
    });
  };

  return (
    <Modal
      open={appointment !== null}
      onClose={onClose}
      title="Log visit outcome"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving || missingActivityDetail}>
            {isSaving ? 'Saving…' : 'Log visit'}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div>
          <Label htmlFor="ca-outcome">Outcome</Label>
          <Select
            id="ca-outcome"
            value={outcome}
            onChange={(event) =>
              setOutcome(event.target.value as AppointmentOutcome)
            }
          >
            {APPOINTMENT_OUTCOME_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="ca-activity">Activity type</Label>
          <Select
            id="ca-activity"
            value={activityType}
            onChange={(event) =>
              setActivityType(event.target.value as ActivityType | '')
            }
          >
            <option value="">Not recorded</option>
            {ACTIVITY_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </div>
        {needsActivityDetail && (
          <div>
            <Label htmlFor="ca-activity-other">Describe the activity</Label>
            <Input
              id="ca-activity-other"
              value={activityTypeOther}
              placeholder="Required when the type is other"
              onChange={(event) => setActivityTypeOther(event.target.value)}
            />
            {touched && missingActivityDetail && (
              <p className="mt-1 text-xs text-destructive">
                A short description is required when the type is “other”.
              </p>
            )}
          </div>
        )}
        <div>
          <Label htmlFor="ca-notes">Visit notes</Label>
          <Textarea
            id="ca-notes"
            value={visitNotes}
            onChange={(event) => setVisitNotes(event.target.value)}
          />
        </div>

        <fieldset className="space-y-3 rounded-md border border-border px-4 py-3">
          <legend className="px-1 text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            Next steps {nextStepsDueDate ? '(reminder will be created)' : '(optional)'}
          </legend>
          <div>
            <Label htmlFor="ca-nextsteps">What did we promise?</Label>
            <Input
              id="ca-nextsteps"
              value={nextSteps}
              placeholder="e.g. send the hospice eligibility one-pager to Dr. Chen"
              onChange={(event) => setNextSteps(event.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="ca-nextsteps-due">Due by</Label>
            <Input
              id="ca-nextsteps-due"
              type="date"
              value={nextStepsDueDate}
              onChange={(event) => setNextStepsDueDate(event.target.value)}
            />
            <p className="mt-1 text-xs text-muted-soft">
              Setting a date creates a reminder assigned to this visit's rep.
            </p>
          </div>
        </fieldset>

        <fieldset className="space-y-3 rounded-md border border-border px-4 py-3">
          <legend className="px-1 text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            Follow-up job {willChain ? '(will be created)' : '(optional)'}
          </legend>
          <div>
            <Label htmlFor="ca-jobtype">Type</Label>
            <Select
              id="ca-jobtype"
              value={nextJobType}
              onChange={(event) =>
                setNextJobType(event.target.value as JobType | '')
              }
            >
              <option value="">Default (follow-up)</option>
              {JOB_TYPE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="ca-objective">Objective</Label>
            <Input
              id="ca-objective"
              value={nextJobObjective}
              onChange={(event) => setNextJobObjective(event.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="ca-due">Due date</Label>
            <Input
              id="ca-due"
              type="date"
              value={nextJobDueDate}
              onChange={(event) => setNextJobDueDate(event.target.value)}
            />
          </div>
        </fieldset>
      </div>
    </Modal>
  );
}
