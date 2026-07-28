import { useState } from 'react';
import { Button, Input, Label, Select, Textarea } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import { JOB_TYPE_OPTIONS } from '@/modules/jobs/constants/jobsConstants';
import type { JobType } from '@/modules/jobs/types/jobsTypes';
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
 * Logs the visit outcome. A `follow_up_needed` outcome makes the backend chain a
 * follow-up job automatically; the optional overrides below shape that job. The
 * chaining note is shown so the automation is never a surprise.
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
  const [nextJobType, setNextJobType] = useState<JobType | ''>('');
  const [nextJobObjective, setNextJobObjective] = useState('');
  const [nextJobDueDate, setNextJobDueDate] = useState('');

  const willChain =
    outcome === AppointmentOutcome.FollowUpNeeded ||
    nextJobType !== '' ||
    nextJobObjective.trim() !== '' ||
    nextJobDueDate !== '';

  const submit = () => {
    if (!appointment) return;
    onSubmit(appointment.id, {
      outcome,
      visitNotes: visitNotes.trim() || undefined,
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
          <Button onClick={submit} disabled={isSaving}>
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
          <Label htmlFor="ca-notes">Visit notes</Label>
          <Textarea
            id="ca-notes"
            value={visitNotes}
            onChange={(event) => setVisitNotes(event.target.value)}
          />
        </div>

        <fieldset className="space-y-3 rounded-md border border-white/[0.06] px-4 py-3">
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
