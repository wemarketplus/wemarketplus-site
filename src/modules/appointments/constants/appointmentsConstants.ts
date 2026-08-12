import type { PillProps } from '@/shared/ui/data-display';
import {
  AppointmentOutcome,
  AppointmentStatus,
  AppointmentType,
} from '../types/appointmentsTypes';

export const APPOINTMENTS_TAGS = {
  List: 'Appointments.List',
  Detail: 'Appointments.Detail',
  Calendar: 'Appointments.Calendar',
} as const;

export const APPOINTMENT_TYPE_LABELS: Record<AppointmentType, string> = {
  [AppointmentType.InPerson]: 'In person',
  [AppointmentType.Call]: 'Call',
  [AppointmentType.Virtual]: 'Virtual',
};

export const APPOINTMENT_STATUS_LABELS: Record<AppointmentStatus, string> = {
  [AppointmentStatus.Scheduled]: 'Scheduled',
  [AppointmentStatus.Completed]: 'Completed',
  [AppointmentStatus.NoShow]: 'No-show',
  [AppointmentStatus.Cancelled]: 'Cancelled',
  [AppointmentStatus.Rescheduled]: 'Rescheduled',
};

export const APPOINTMENT_STATUS_PILL: Record<
  AppointmentStatus,
  PillProps['tone']
> = {
  [AppointmentStatus.Scheduled]: 'b',
  [AppointmentStatus.Completed]: 'g',
  [AppointmentStatus.NoShow]: 'r',
  [AppointmentStatus.Cancelled]: 'r',
  [AppointmentStatus.Rescheduled]: 'y',
};

export const APPOINTMENT_OUTCOME_LABELS: Record<AppointmentOutcome, string> = {
  [AppointmentOutcome.Positive]: 'Positive',
  [AppointmentOutcome.Neutral]: 'Neutral',
  [AppointmentOutcome.FollowUpNeeded]: 'Follow-up needed',
};

export const APPOINTMENT_OUTCOME_OPTIONS: ReadonlyArray<{
  value: AppointmentOutcome;
  label: string;
}> = Object.values(AppointmentOutcome).map((value) => ({
  value,
  label: APPOINTMENT_OUTCOME_LABELS[value],
}));

export const APPOINTMENT_TYPE_OPTIONS: ReadonlyArray<{
  value: AppointmentType;
  label: string;
}> = Object.values(AppointmentType).map((value) => ({
  value,
  label: APPOINTMENT_TYPE_LABELS[value],
}));

export const APPOINTMENT_STATUS_CHIPS: ReadonlyArray<{
  value: AppointmentStatus | 'all';
  label: string;
}> = [
  { value: 'all', label: 'All statuses' },
  ...Object.values(AppointmentStatus).map((value) => ({
    value,
    label: APPOINTMENT_STATUS_LABELS[value],
  })),
];

/** Default calendar window: the current month plus the next, in days. */
export const CALENDAR_DEFAULT_WINDOW_DAYS = 60;

/**
 * How far back the agenda reaches for visits that are still OPEN.
 *
 * The agenda used to start at today 00:00, so a visit still marked `scheduled`
 * from yesterday simply vanished — the nurse's guide says "use the My Calendar
 * view to see just your own scheduled visits", and a nurse whose only open visit
 * was yesterday read an empty list as a broken calendar. The agenda already styles
 * past-due visits in red (`isPastDue`), which the forward-only window made almost
 * unreachable: nothing before today could ever be in the feed.
 *
 * Two weeks, not unbounded: this is a "you still owe this" tail, not visit history.
 * Completed and cancelled visits in that tail are dropped by the hook — only the
 * outstanding ones come forward.
 */
export const CALENDAR_PAST_DUE_LOOKBACK_DAYS = 14;
