import type { ID, ISODateString } from '@/shared/types';

/**
 * What kind of thing is on the calendar.
 *
 * Deliberately only the two the guide names — "You can schedule a tour, a
 * facility visit, or even a physician lunch directly" — where a physician lunch
 * is a facility visit with a `lunch_and_learn` type, not a third record. Tasks
 * are NOT here: Task Manager and Daily Task already own due-dated work, and
 * putting them on the calendar too would mean three screens showing the same row.
 */
export const ClCalendarEventKind = {
  Tour: 'tour',
  Visit: 'visit',
} as const;
export type ClCalendarEventKind =
  (typeof ClCalendarEventKind)[keyof typeof ClCalendarEventKind];

/**
 * One row on the shared calendar, normalised from a tour or an outreach visit.
 *
 * A single view-model rather than a discriminated union of the two records: the
 * month grid, the day panel and the colour logic all want the same four facts
 * (when, what, whose, where it links), and every one of them would otherwise
 * carry a switch on the record type.
 */
export interface ClCalendarEvent {
  /** Prefixed by kind — a tour and a visit could share a bare uuid. */
  id: string;
  kind: ClCalendarEventKind;
  /** Local-day bucket, `YYYY-MM-DD`. */
  dayKey: string;
  /** Full instant for tours; midnight local for visits (see ownerId note). */
  at: ISODateString;
  /** True when `at` carries a meaningful clock time, not just a date. */
  hasTime: boolean;
  title: string;
  /** Secondary line: contact, location, visit type. */
  detail: string;
  /**
   * Whose event this is, or null when the record does not say.
   *
   * Tours carry `guideUserId`. OUTREACH VISITS CARRY NO OWNER AT ALL — the
   * cl/outreach-visits DTO has no user field — so every visit is null here and
   * renders in the unassigned colour. That is why `scope: 'mine'` cannot filter
   * them; see useClCalendar.
   */
  ownerId: ID | null;
  /** Where the row can actually be edited. */
  to: string;
  /** Cancelled/no-show rows render struck through rather than disappearing. */
  isCancelled: boolean;
}

/** "Use the dropdown to switch between My Calendar and All Users". */
export type ClCalendarScope = 'mine' | 'all';

/** One cell of the month grid. Always 42, so the grid height never jumps. */
export interface ClCalendarCell {
  date: Date;
  key: string;
  inMonth: boolean;
  isToday: boolean;
  items: ClCalendarEvent[];
}
