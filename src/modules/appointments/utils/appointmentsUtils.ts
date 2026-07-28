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

/** YYYY-MM-DD for the LOCAL calendar day (never via toISOString/UTC). */
export function localDateKey(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/** One cell in the month grid. */
export interface CalendarCell {
  date: Date;
  key: string;
  inMonth: boolean;
  isToday: boolean;
  items: AppointmentRecord[];
}

/**
 * Builds a 6-row Monday-first month grid for `month`, bucketing appointments into
 * their local calendar day. Always 42 cells so the grid height never jumps
 * between months.
 */
export function buildMonthGrid(
  month: Date,
  appointments: readonly AppointmentRecord[],
  today = new Date(),
): CalendarCell[] {
  const byDay = new Map<string, AppointmentRecord[]>();
  for (const appointment of appointments) {
    // Bucket by the LOCAL day of startAt, not the UTC slice — a 9pm visit must
    // not land on tomorrow for users ahead of UTC.
    const key = localDateKey(new Date(appointment.startAt));
    const bucket = byDay.get(key);
    if (bucket) {
      bucket.push(appointment);
    } else {
      byDay.set(key, [appointment]);
    }
  }

  const firstOfMonth = new Date(month.getFullYear(), month.getMonth(), 1);
  // Monday-first: JS getDay() is Sunday-0, so shift Sunday to the end.
  const leading = (firstOfMonth.getDay() + 6) % 7;
  const gridStart = new Date(firstOfMonth);
  gridStart.setDate(gridStart.getDate() - leading);

  const todayKey = localDateKey(today);
  const cells: CalendarCell[] = [];
  for (let index = 0; index < 42; index += 1) {
    const date = new Date(gridStart);
    date.setDate(gridStart.getDate() + index);
    const key = localDateKey(date);
    cells.push({
      date,
      key,
      inMonth: date.getMonth() === month.getMonth(),
      isToday: key === todayKey,
      items: byDay.get(key) ?? [],
    });
  }
  return cells;
}

/** The calendar feed window covering the whole visible grid of `month`. */
export function monthWindow(month: Date): { from: string; to: string } {
  const firstOfMonth = new Date(month.getFullYear(), month.getMonth(), 1);
  const leading = (firstOfMonth.getDay() + 6) % 7;
  const from = new Date(firstOfMonth);
  from.setDate(from.getDate() - leading);
  from.setHours(0, 0, 0, 0);
  const to = new Date(from);
  to.setDate(to.getDate() + 42);
  return { from: from.toISOString(), to: to.toISOString() };
}

/** Month label, e.g. "July 2026". */
export function monthLabel(month: Date): string {
  return month.toLocaleDateString(undefined, {
    month: 'long',
    year: 'numeric',
  });
}

export const WEEKDAY_LABELS: ReadonlyArray<string> = [
  'Mon',
  'Tue',
  'Wed',
  'Thu',
  'Fri',
  'Sat',
  'Sun',
];
