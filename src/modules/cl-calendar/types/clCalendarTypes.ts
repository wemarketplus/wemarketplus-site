import type { ID, ISODateString } from '@/shared/types';

/**
 * What kind of thing is on the calendar.
 *
 * Deliberately only the two the guide names — "You can schedule a tour, a
 * facility visit, or even a physician lunch directly" — where a physician lunch
 * is an outreach visit with the `lunch_learn` type, not a third record. Which is
 * exactly why `typeLabel` below exists: two kinds cannot name three things, and
 * for a while they did not — every visit read as "Facility visit". Tasks
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
  /** Full instant for tours; midnight local for visits (see visitToEvent). */
  at: ISODateString;
  /** True when `at` carries a meaningful clock time, not just a date. */
  hasTime: boolean;
  title: string;
  /**
   * What this row IS, in the words the user picked it by — "Tour",
   * "Facility visit", "Lunch & learn".
   *
   * Distinct from `kind`, and that distinction is the bug it exists for. `kind`
   * has two members because there are two TABLES behind the calendar, so every
   * outreach visit — facility visit, physician lunch, drop-off — resolved to the
   * single label "Facility visit" and a physician lunch was rendered as a
   * facility visit from the moment it was created. The type the user actually
   * chose lives on the record (`visitType`), so it is carried here rather than
   * re-derived: the day panel and the month grid must not each own a switch on
   * the record type to answer the same question.
   */
  typeLabel: string;
  /** Secondary line: contact, location, visit type. */
  detail: string;
  /**
   * Whose event this is, or null when the record does not say.
   *
   * Outreach visits ALWAYS say: `cl_outreach_visits.userId` is NOT NULL and is
   * set from the caller's JWT, so a visit's owner is the rep who logged it. (An
   * earlier version of this note claimed visits carried no owner at all and the
   * mapper hardcoded null to match — wrong on both counts, and the reason a
   * user's chosen colour never appeared on this calendar.)
   *
   * Tours may still be null: `cl_tours.guideUserId` is nullable and both tour
   * forms offer an explicit "— Unassigned —", so an unassigned tour is a real
   * state the product supports, not a data defect. Null therefore means exactly
   * one thing now — nobody is on the hook for this yet — and it renders in the
   * unassigned grey. `scope: 'mine'` keeps those rows visible; see useClCalendar.
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
