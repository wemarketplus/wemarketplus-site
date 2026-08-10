import { useState } from 'react';
import { Button, Input, Label, Select } from '@/shared/ui/core';
import { Modal } from '@/shared/ui/feedback';
import {
  ACTIVITY_TYPE_OPTIONS,
  ActivityType,
} from '@/shared/constants/activityTypeConstants';
import { APPOINTMENT_TYPE_LABELS } from '../constants/appointmentsConstants';
import { AppointmentType } from '../types/appointmentsTypes';
import type { ScheduleVisitRequest } from '../types/appointmentsTypes';

interface ScheduleVisitModalProps {
  open: boolean;
  isSaving: boolean;
  /** The record this visit is about — a prospect or a facility, never both. */
  target: Pick<ScheduleVisitRequest, 'pipelineId' | 'companyId' | 'contactId'>;
  /** Shown in the heading so the user knows what they are booking against. */
  subjectName: string;
  onClose: () => void;
  onSubmit: (body: ScheduleVisitRequest) => Promise<boolean>;
}

/** Default slot length. A drop-off is short; the user can change the end time. */
const DEFAULT_DURATION_MINUTES = 30;

/** `datetime-local` wants `YYYY-MM-DDTHH:mm` in LOCAL time, not an ISO instant. */
const toLocalInput = (d: Date): string => {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

const defaultStart = (): Date => {
  const d = new Date();
  d.setMinutes(0, 0, 0);
  d.setHours(d.getHours() + 1);
  return d;
};

export function ScheduleVisitModal({
  open,
  isSaving,
  target,
  subjectName,
  onClose,
  onSubmit,
}: ScheduleVisitModalProps) {
  const start = defaultStart();
  const [values, setValues] = useState({
    title: '',
    startAt: toLocalInput(start),
    endAt: toLocalInput(
      new Date(start.getTime() + DEFAULT_DURATION_MINUTES * 60_000),
    ),
    appointmentType: AppointmentType.InPerson as AppointmentType,
    activityType: ActivityType.FacilityOfficeVisit as ActivityType,
    location: '',
  });
  const [error, setError] = useState<string | null>(null);

  const set = <K extends keyof typeof values>(
    key: K,
    value: (typeof values)[K],
  ) => setValues((v) => ({ ...v, [key]: value }));

  const close = () => {
    setError(null);
    onClose();
  };

  const submit = async () => {
    if (!values.title.trim()) {
      setError('Give the visit a title.');
      return;
    }
    const startAt = new Date(values.startAt);
    const endAt = new Date(values.endAt);
    // Checked here as well as server-side so the user is told immediately rather
    // than after a round trip; the backend remains the authority.
    if (!(endAt > startAt)) {
      setError('The end time must be after the start time.');
      return;
    }
    setError(null);
    const ok = await onSubmit({
      ...target,
      title: values.title.trim(),
      // Converted to a real instant: the inputs are local wall-clock, and the
      // API stores timestamptz.
      startAt: startAt.toISOString(),
      endAt: endAt.toISOString(),
      appointmentType: values.appointmentType,
      activityType: values.activityType,
      location: values.location.trim() || undefined,
    });
    if (ok) close();
  };

  return (
    <Modal
      open={open}
      onClose={close}
      title={`Schedule visit — ${subjectName}`}
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={isSaving}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={isSaving}>
            {isSaving ? 'Scheduling…' : 'Schedule visit'}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <Label htmlFor="sv-title">Title</Label>
          <Input
            id="sv-title"
            value={values.title}
            onChange={(e) => set('title', e.target.value)}
            placeholder="Drop off brochures with the ICU team"
          />
        </div>

        <div>
          <Label htmlFor="sv-start">Starts</Label>
          <Input
            id="sv-start"
            type="datetime-local"
            value={values.startAt}
            onChange={(e) => set('startAt', e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="sv-end">Ends</Label>
          <Input
            id="sv-end"
            type="datetime-local"
            value={values.endAt}
            onChange={(e) => set('endAt', e.target.value)}
          />
        </div>

        <div>
          <Label htmlFor="sv-channel">How</Label>
          <Select
            id="sv-channel"
            value={values.appointmentType}
            onChange={(e) =>
              set('appointmentType', e.target.value as AppointmentType)
            }
          >
            {Object.values(AppointmentType).map((t) => (
              <option key={t} value={t}>
                {APPOINTMENT_TYPE_LABELS[t]}
              </option>
            ))}
          </Select>
        </div>
        <div>
          <Label htmlFor="sv-activity">What</Label>
          <Select
            id="sv-activity"
            value={values.activityType}
            onChange={(e) => set('activityType', e.target.value as ActivityType)}
          >
            {ACTIVITY_TYPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        </div>

        <div className="sm:col-span-2">
          <Label htmlFor="sv-location">Location</Label>
          <Input
            id="sv-location"
            value={values.location}
            onChange={(e) => set('location', e.target.value)}
          />
        </div>

        {error && (
          <p className="text-[12px] text-destructive sm:col-span-2">{error}</p>
        )}
        <p className="text-[11px] text-muted-soft sm:col-span-2">
          This creates the visit on your calendar and the field work behind it.
        </p>
      </div>
    </Modal>
  );
}
