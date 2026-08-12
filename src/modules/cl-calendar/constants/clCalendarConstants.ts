import { ClCalendarEventKind } from '../types/clCalendarTypes';

/**
 * How many tours / visits the calendar loads.
 *
 * Neither /cl/tours nor /cl/outreach-visits accepts a date range, so the calendar
 * cannot ask for "the visible month" — it loads a page and buckets it. 200 covers
 * roughly a year of ordinary activity for a single community, which is what makes
 * month navigation feel instant (no refetch) at the cost of a month far outside
 * the page reading as empty. A `from`/`to` filter on those endpoints is what turns
 * this into a real windowed query.
 */
export const CL_CALENDAR_FETCH_LIMIT = 200;

/** Events drawn per cell before collapsing into "+N more". */
export const CL_MAX_CHIPS_PER_DAY = 2;

/** What to call each kind in the day panel and the schedule modal. */
export const CL_EVENT_KIND_LABELS: Record<ClCalendarEventKind, string> = {
  [ClCalendarEventKind.Tour]: 'Tour',
  [ClCalendarEventKind.Visit]: 'Facility visit',
};

/**
 * What the schedule modal can create, in the guide's words: "You can schedule a
 * tour, a facility visit, or even a physician lunch directly."
 *
 * A physician lunch is a VISIT with the `lunch_and_learn` type, not a third
 * record — so it appears here as its own choice (the guide names it, and a user
 * looking for it should find it) that pre-selects that visit type.
 */
export const CL_SCHEDULE_CHOICES: ReadonlyArray<{
  value: string;
  label: string;
  hint: string;
}> = [
  { value: 'tour', label: 'Tour', hint: 'A family touring the community' },
  {
    value: 'visit',
    label: 'Facility visit',
    hint: 'A referral source call, drop-in or drop-off',
  },
  {
    value: 'lunch',
    label: 'Physician lunch',
    hint: 'A lunch & learn with a referring practice',
  },
];
