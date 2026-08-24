import { CL_TOUR_STATUS, type ClTourRecord } from '@/modules/cl-tours';
import { visitTypeLabel, type ClOutreachVisitRecord } from '@/modules/cl-outreach';
import {
  ClCalendarEventKind,
  type ClCalendarCell,
  type ClCalendarEvent,
} from '../types/clCalendarTypes';

/** Monday-first, matching the HospiceLink calendar's rail. */
export const CL_WEEKDAY_LABELS: readonly string[] = [
  'Mon',
  'Tue',
  'Wed',
  'Thu',
  'Fri',
  'Sat',
  'Sun',
];

/**
 * `YYYY-MM-DD` for the LOCAL calendar day.
 *
 * Never `toISOString().slice(0,10)`: that yields the UTC day, so a 7pm tour in
 * UTC-5 lands on tomorrow and the row shows up on the wrong square.
 */
export function clLocalDateKey(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/** "2p" / "10:30a" — the compact month-view clock. */
export function clShortTime(iso: string): string {
  const date = new Date(iso);
  const hour = date.getHours();
  const minute = date.getMinutes();
  const suffix = hour < 12 ? 'a' : 'p';
  const base = hour % 12 === 0 ? 12 : hour % 12;
  return minute === 0
    ? `${base}${suffix}`
    : `${base}:${String(minute).padStart(2, '0')}${suffix}`;
}

export function clMonthLabel(month: Date): string {
  return month.toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
}

/** Tour → calendar row. `leadLabel` is resolved by the caller (id → name). */
export function tourToEvent(
  tour: ClTourRecord,
  leadLabel: string,
): ClCalendarEvent {
  return {
    id: `tour:${tour.id}`,
    kind: ClCalendarEventKind.Tour,
    dayKey: clLocalDateKey(new Date(tour.scheduledAt)),
    at: tour.scheduledAt,
    hasTime: true,
    title: `Tour — ${leadLabel}`,
    detail: [
      tour.durationMin ? `${tour.durationMin} min` : null,
      tour.outcome,
    ]
      .filter(Boolean)
      .join(' · '),
    ownerId: tour.guideUserId,
    to: '/tours',
    isCancelled:
      tour.status === CL_TOUR_STATUS.Cancelled ||
      tour.status === CL_TOUR_STATUS.NoShow,
  };
}

/**
 * Outreach visit → calendar row.
 *
 * `visitDate` is a DATE column with no clock, so `hasTime` is false and the row
 * renders without a time chip rather than claiming a spurious midnight. Parsed
 * by splitting the string instead of `new Date('2026-08-11')`, which JS reads as
 * UTC midnight and would shift the row a day back west of Greenwich.
 *
 * `ownerId` is `visit.userId`. This used to be hardcoded `null` on the stated
 * grounds that "outreach visits carry no owner at all — the DTO has no user
 * field". That was never true of the API: `cl_outreach_visits.userId` is NOT
 * NULL, the create endpoint fills it from the caller's JWT, and the list
 * endpoint returns the entity with the field on it. Only this frontend record
 * type omitted it, so the owner was discarded here and every facility visit and
 * physician lunch rendered in the grey UNASSIGNED colour — which is what made a
 * user's chosen profile colour appear to do nothing on the calendar
 * CommunityLink actually lands them on.
 */
export function visitToEvent(visit: ClOutreachVisitRecord): ClCalendarEvent {
  const [year, month, day] = visit.visitDate.slice(0, 10).split('-').map(Number);
  const local = new Date(year, (month ?? 1) - 1, day ?? 1);

  return {
    id: `visit:${visit.id}`,
    kind: ClCalendarEventKind.Visit,
    dayKey: clLocalDateKey(local),
    at: local.toISOString(),
    hasTime: false,
    title: visit.locationName?.trim()
      ? `Visit — ${visit.locationName}`
      : 'Facility visit',
    detail: [visit.contactName, visitTypeLabel(visit.visitType)]
      .filter(Boolean)
      .join(' · '),
    ownerId: visit.userId,
    to: '/outreach/log',
    isCancelled: false,
  };
}

/**
 * The 42-cell Monday-first grid for `month`, with events bucketed by local day
 * and sorted within each cell so a day reads top-to-bottom in time order.
 */
export function buildClMonthGrid(
  month: Date,
  events: readonly ClCalendarEvent[],
  today: Date = new Date(),
): ClCalendarCell[] {
  const byDay = new Map<string, ClCalendarEvent[]>();
  for (const event of events) {
    const bucket = byDay.get(event.dayKey);
    if (bucket) bucket.push(event);
    else byDay.set(event.dayKey, [event]);
  }
  // All-day rows (visits) sort before timed ones within a day: they are the
  // day's context, and a visit with no clock has no place in a time sequence.
  for (const bucket of byDay.values()) {
    bucket.sort((a, b) => {
      if (a.hasTime !== b.hasTime) return a.hasTime ? 1 : -1;
      return a.at < b.at ? -1 : 1;
    });
  }

  const firstOfMonth = new Date(month.getFullYear(), month.getMonth(), 1);
  // getDay() is Sunday-0; shift so Monday leads.
  const leading = (firstOfMonth.getDay() + 6) % 7;
  const gridStart = new Date(firstOfMonth);
  gridStart.setDate(gridStart.getDate() - leading);

  const todayKey = clLocalDateKey(today);
  const cells: ClCalendarCell[] = [];
  for (let index = 0; index < 42; index += 1) {
    const date = new Date(gridStart);
    date.setDate(gridStart.getDate() + index);
    const key = clLocalDateKey(date);
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
