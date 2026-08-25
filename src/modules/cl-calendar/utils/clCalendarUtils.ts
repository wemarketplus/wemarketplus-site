import { CL_TOUR_STATUS, type ClTourRecord } from '@/modules/cl-tours';
import { visitTypeLabel, type ClOutreachVisitRecord } from '@/modules/cl-outreach';
import { isoToLocalInput, nowLocalDateTime } from '@/shared/utils/dateFormatter';
import { CL_EVENT_KIND_LABELS } from '../constants/clCalendarConstants';
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

/** The default clock a tour is seeded at when a day cell is clicked. */
const TOUR_SEED_TIME = '10:00';
/** Rounding for the fallback below — a picker offering 14:07 reads as a glitch. */
const SEED_STEP_MIN = 15;

/**
 * The `datetime-local` value to seed a tour with for the day the user clicked.
 *
 * 10:00 on that day, EXCEPT when the day is today and 10:00 has already gone —
 * then the next quarter hour, so the form does not open on a time its own
 * past-date rule immediately rejects. Clicking "today" at 14:30 and being shown
 * a red error before touching anything is a worse bug than the one the rule
 * fixes.
 *
 * A PAST day is deliberately left at 10:00: there is no valid time on it, and
 * silently moving the user to a different day would hide which square they hit.
 * The schema rejects it and says so.
 */
export function clSeedTourWhen(dayKey: string): string {
  if (!dayKey) return '';
  const atSeed = `${dayKey}T${TOUR_SEED_TIME}`;
  const now = nowLocalDateTime();
  if (atSeed >= now || dayKey !== now.slice(0, 10)) return atSeed;

  const next = new Date();
  next.setSeconds(0, 0);
  next.setMinutes(next.getMinutes() + (SEED_STEP_MIN - (next.getMinutes() % SEED_STEP_MIN)));
  const rounded = isoToLocalInput(next);
  // Rounding up late in the evening can cross midnight; stay on the day the user
  // actually clicked rather than quietly booking the next one.
  return rounded.slice(0, 10) === dayKey ? rounded : `${dayKey}T23:59`;
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
    typeLabel: CL_EVENT_KIND_LABELS[ClCalendarEventKind.Tour],
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

  /**
   * The row's OWN type, which is what the user picked — not the kind.
   *
   * This is the read half of the physician-lunch bug: the title used to be the
   * literal `'Visit — …'` / `'Facility visit'` and `visitType` only reached the
   * small secondary line, so a physician lunch was stored correctly and then
   * rendered as a facility visit in both the month grid (which draws `title`)
   * and the day panel (which drew the kind label). Nothing was lost on the
   * write; the read threw the answer away.
   *
   * A row with no type at all keeps the old generic wording rather than showing
   * `visitTypeLabel`'s "—" as a title — historical rows predate the picker.
   */
  const typeLabel = visit.visitType
    ? visitTypeLabel(visit.visitType)
    : CL_EVENT_KIND_LABELS[ClCalendarEventKind.Visit];

  return {
    id: `visit:${visit.id}`,
    kind: ClCalendarEventKind.Visit,
    dayKey: clLocalDateKey(local),
    at: local.toISOString(),
    hasTime: false,
    typeLabel,
    title: visit.locationName?.trim()
      ? `${typeLabel} — ${visit.locationName}`
      : typeLabel,
    // The type has moved UP into the title, so repeating it here would say the
    // same thing twice on two lines.
    detail: visit.contactName ?? '',
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
