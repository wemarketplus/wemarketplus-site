import { format, formatDistanceToNow, parseISO } from 'date-fns';

const toDate = (value: string | Date): Date =>
  typeof value === 'string' ? parseISO(value) : value;

export const formatDate = (value: string | Date, pattern = 'PP'): string =>
  format(toDate(value), pattern);

export const formatDateTime = (value: string | Date): string =>
  format(toDate(value), 'PPp');

export const formatRelative = (value: string | Date): string =>
  formatDistanceToNow(toDate(value), { addSuffix: true });

// --- datetime-local input <-> ISO ------------------------------------------
// A `datetime-local` input reads and writes a zoneless local wall-clock string
// ("2026-06-25T14:30"), while the backend stores a `timestamptz`. Convert on
// both edges so the instant survives the round trip and the user sees the time
// in their own zone. Never slice an ISO string to build the input value: that
// yields UTC wall-clock and shows the wrong time outside UTC.

/** ISO timestamp -> the value a `datetime-local` input expects (local time). */
export const isoToLocalInput = (value: string | Date): string => {
  const d = toDate(value);
  return Number.isNaN(d.getTime()) ? '' : format(d, "yyyy-MM-dd'T'HH:mm");
};

/** `datetime-local` value (local wall clock) -> ISO instant, or '' if unparseable. */
export const localInputToIso = (local: string): string => {
  const ms = Date.parse(local);
  return Number.isNaN(ms) ? '' : new Date(ms).toISOString();
};

/**
 * Today's date, local wall-clock, as a `date` input expects ("yyyy-MM-dd").
 *
 * NOT `new Date().toISOString().slice(0, 10)` — that reads the UTC calendar
 * day, which is tomorrow's date for part of the evening in every zone west of
 * UTC (and yesterday's for part of the morning east of it). Same off-by-one
 * class of bug isoToLocalInput above exists to avoid.
 */
export const todayLocalDate = (): string => format(new Date(), 'yyyy-MM-dd');
