import { CALENDAR_DEFAULT_WINDOW_DAYS } from '../constants/appointmentsConstants';
import {
  AppointmentStatus,
  type AppointmentRecord,
} from '../types/appointmentsTypes';

/** The default calendar window: today through +N days, as ISO instants. */
export function defaultCalendarWindow(now = new Date()): {
  from: string;
  to: string;
} {
  const from = new Date(now);
  from.setHours(0, 0, 0, 0);
  const to = new Date(from);
  to.setDate(to.getDate() + CALENDAR_DEFAULT_WINDOW_DAYS);
  return { from: from.toISOString(), to: to.toISOString() };
}

/** A scheduled visit whose start time has already passed. */
export function isPastDue(
  appointment: AppointmentRecord,
  now = new Date(),
): boolean {
  return (
    appointment.status === AppointmentStatus.Scheduled &&
    new Date(appointment.startAt).getTime() < now.getTime()
  );
}

/** Only a not-yet-finished visit can be completed. */
export function isCompletable(appointment: AppointmentRecord): boolean {
  return (
    appointment.status !== AppointmentStatus.Completed &&
    appointment.status !== AppointmentStatus.Cancelled
  );
}

/** Short "3:00 PM – 4:00 PM" range label. */
export function timeRange(appointment: AppointmentRecord): string {
  const fmt = (value: string) =>
    new Date(value).toLocaleTimeString(undefined, {
      hour: 'numeric',
      minute: '2-digit',
    });
  return `${fmt(appointment.startAt)} – ${fmt(appointment.endAt)}`;
}

/** Groups a flat feed into date buckets (YYYY-MM-DD) for a day-by-day calendar. */
export function groupByDay(
  appointments: readonly AppointmentRecord[],
): ReadonlyArray<{ date: string; items: AppointmentRecord[] }> {
  const buckets = new Map<string, AppointmentRecord[]>();
  for (const appointment of appointments) {
    const key = appointment.startAt.slice(0, 10);
    const bucket = buckets.get(key);
    if (bucket) {
      bucket.push(appointment);
    } else {
      buckets.set(key, [appointment]);
    }
  }
  // The feed already arrives ascending by startAt, so insertion order is the
  // chronological order — no re-sort needed.
  return [...buckets.entries()].map(([date, items]) => ({ date, items }));
}
