import { useState } from 'react';
import {
  EMPTY_LOCATION,
  LocationField,
  fromLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import { useTenantStaffOptions } from '@/modules/users';
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

/**
 * The location as the three fields the request carries.
 *
 * Coordinates are dropped for anything but an in-person visit: switching the
 * type after picking a place would otherwise leave a video call pinned to a
 * building nobody is driving to.
 */
const locationFields = (
  location: LocationValue,
  appointmentType: AppointmentType,
) => {
  const { label, lat, lng } = fromLocationValue(location);
  return appointmentType === AppointmentType.InPerson
    ? { location: label, locationLat: lat, locationLng: lng }
    : { location: label };
};

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
    // A place, not a string: the label is what the calendar shows, the
    // coordinates are what say WHICH "main campus" it was.
    location: EMPTY_LOCATION as LocationValue,
    /**
     * WHO IS DOING THE VISIT — blank means "me".
     *
     * Left blank rather than pre-filled with the signed-in user: the server already
     * defaults `assignedRep` to the caller, so an empty value and the caller's own
     * id mean the same thing, and pre-selecting a name would make "assign this to a
     * nurse" look like a change of owner rather than the normal case.
     */
    assignedRep: '',
  });
  const [error, setError] = useState<string | null>(null);
  // Only fetched while the modal is open — a closed form should not hold a
  // subscription to the directory.
  const staff = useTenantStaffOptions(open);

  /**
   * The map picker is for in-person visits only. A video call or a phone call
   * has a link or a number in this field, and neither has a place on a map.
   */
  const isInPerson = values.appointmentType === AppointmentType.InPerson;

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
      // Omitted entirely when blank. Sending `undefined` lets the server apply its
      // own default (the caller); sending an empty string would fail @IsUUID.
      ...(values.assignedRep ? { assignedRep: values.assignedRep } : {}),
      ...locationFields(values.location, values.appointmentType),
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

        {/* The assignment that makes the visit somebody's work. Without it every
            visit lands on the person who booked it, so a nurse or caregiver never
            acquires a patient and their Family communication / Notes screens have
            nothing to write against. */}
        <div className="sm:col-span-2">
          <Label htmlFor="sv-assignee">Assign to</Label>
          <Select
            id="sv-assignee"
            value={values.assignedRep}
            onChange={(e) => set('assignedRep', e.target.value)}
            disabled={staff.isLoading}
          >
            <option value="">— Me —</option>
            {staff.options.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
          <p className="mt-1 text-[11px] text-muted-soft">
            Assigning a nurse or caregiver is what puts this patient on their “My
            patients” list.
          </p>
        </div>

        <div className="sm:col-span-2">
          {isInPerson ? (
            <LocationField
              id="sv-location"
              label="Location"
              value={values.location}
              onChange={(next) => set('location', next)}
              placeholder="Search or drop a pin"
            />
          ) : (
            <>
              <Label htmlFor="sv-location">Location</Label>
              <Input
                id="sv-location"
                value={values.location.label}
                onChange={(e) =>
                  set('location', { label: e.target.value, coords: null })
                }
                placeholder="Meeting link or number"
              />
            </>
          )}
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
