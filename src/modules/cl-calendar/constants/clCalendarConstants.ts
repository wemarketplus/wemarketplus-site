import { ClCalendarEventKind } from '../types/clCalendarTypes';

/**
 * How many tours / visits the calendar loads.
 *
 * Neither /cl/tours nor /cl/outreach-visits accepts a date range, so the calendar
 * cannot ask for "the visible month" — it loads a page and buckets it. Month
 * navigation therefore re-buckets one cached page instead of refetching, which is
 * instant, at the cost of a month outside the page reading as empty. A `from`/`to`
 * filter on those endpoints is what turns this into a real windowed query.
 *
 * 100, NOT 200: ClListQueryDto caps `limit` at MAX_LIMIT (100), so every request
 * this page made was answered `400 · limit must not be greater than 100` — the
 * whole screen sat on its "could not load the calendar" state, and the schedule
 * modal's Lead and Referral-source pickers (useClScheduleEvent, same constant)
 * came back empty for the same reason. It went unnoticed because the page was
 * exported but never routed; it is routed now (CalendarRoute), so the ceiling has
 * to be the one the API actually allows. Raising it again means raising MAX_LIMIT
 * on the server first — or, better, adding the date window described above.
 */
export const CL_CALENDAR_FETCH_LIMIT = 100;

/** Events drawn per cell before collapsing into "+N more". */
export const CL_MAX_CHIPS_PER_DAY = 2;

/**
 * What to call each KIND — i.e. each of the two tables behind the calendar.
 *
 * NOT what to call each row: an outreach visit can be a facility visit, a
 * physician lunch or a drop-off, and this map has one entry for all three. It
 * used to be rendered directly in the day panel, which is why a physician lunch
 * appeared there as "Facility visit". Rows now carry their own `typeLabel`
 * (ClCalendarEvent), and these two are its SOURCE for a tour and its FALLBACK
 * for a visit with no type recorded.
 */
export const CL_EVENT_KIND_LABELS: Record<ClCalendarEventKind, string> = {
  [ClCalendarEventKind.Tour]: 'Tour',
  [ClCalendarEventKind.Visit]: 'Facility visit',
};

/**
 * What the schedule modal can create, in the guide's words: "You can schedule a
 * tour, a facility visit, or even a physician lunch directly."
 *
 * A physician lunch is a VISIT with the `lunch_learn` type, not a third
 * record — so it appears here as its own choice (the guide names it, and a user
 * looking for it should find it) that pre-selects that visit type. The value it
 * writes comes from VISIT_TYPE (cl-outreach); it was spelled out by hand here as
 * `lunch_and_learn`, which is a value nothing in either repo recognises.
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
