import { useMemo, useState } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useListClLeadsQuery } from '@/modules/cl-leads';
import { useListClVisitsQuery } from '@/modules/cl-outreach';
import { useListClToursQuery } from '@/modules/cl-tours';
import { CL_CALENDAR_FETCH_LIMIT } from '../constants/clCalendarConstants';
import type {
  ClCalendarCell,
  ClCalendarEvent,
  ClCalendarScope,
} from '../types/clCalendarTypes';
import {
  buildClMonthGrid,
  clLocalDateKey,
  tourToEvent,
  visitToEvent,
} from '../utils/clCalendarUtils';

export interface ClCalendarController {
  month: Date;
  cells: ClCalendarCell[];
  scope: ClCalendarScope;
  setScope: (scope: ClCalendarScope) => void;
  selectedKey: string;
  selectDay: (key: string) => void;
  /** Events on the selected day, in the same order the cell shows them. */
  selectedEvents: ClCalendarEvent[];
  prevMonth: () => void;
  nextMonth: () => void;
  goToday: () => void;
  /**
   * True when at least one loaded row belongs to nobody, so "My calendar" is
   * showing something that is not the viewer's.
   *
   * In practice that now means an UNASSIGNED TOUR and nothing else: visits always
   * have an owner. Kept (rather than deleted with the visit fix) because
   * `cl_tours.guideUserId` is nullable by design — the tour forms offer
   * "— Unassigned —" — so the state it reports is still reachable. Drives the
   * note under the scope toggle. See the ownership note below.
   */
  hasUnownedEvents: boolean;
  isLoading: boolean;
  isFetching: boolean;
  isError: boolean;
}

const startOfMonth = (date: Date) =>
  new Date(date.getFullYear(), date.getMonth(), 1);

/**
 * The CommunityLink shared team calendar.
 *
 * Assembled CLIENT-SIDE from /cl/tours and /cl/outreach-visits because there is
 * no CommunityLink calendar endpoint — HospiceLink's /hl/appointments cannot be
 * reused here: it is product-scoped and every appointment requires a `jobId`,
 * which is an HL pipeline concept CommunityLink has no equivalent of.
 *
 * THE SCOPE CAVEAT, which the UI surfaces rather than hides: "My calendar" can
 * only filter records that say who owns them. Both kinds now do — outreach
 * visits carry `userId` (NOT NULL, set from the caller's JWT) and tours carry
 * `guideUserId` — so scope filtering is honest for every visit and for every
 * assigned tour.
 *
 * What remains is narrower than the caveat this block used to describe: a tour's
 * `guideUserId` is NULLABLE and both tour forms offer "— Unassigned —", so an
 * unassigned tour genuinely belongs to nobody. Those rows stay visible in BOTH
 * scopes rather than vanishing from every calendar in the tenant (nobody would
 * ever see them) or being falsely attributed to whoever is looking.
 * `hasUnownedEvents` lets the scope toggle say so.
 *
 * The previous caveat asserted that visits carried no owner and that the fix was
 * to add a `userId` field to cl/outreach-visits. The backend already had one;
 * the frontend record type was simply missing it, so `visitToEvent` threw the
 * owner away and every visit rendered unowned. See visitToEvent.
 *
 * Fetching is a fixed recent window, not the visible month: neither endpoint
 * takes a date range, so month navigation re-buckets what is already cached
 * instead of refetching. Months outside the fetched rows read as empty — see
 * CL_CALENDAR_FETCH_LIMIT.
 */
export function useClCalendar(): ClCalendarController {
  const userId = useAppSelector((s) => s.auth.user?.id ?? null);
  const [month, setMonth] = useState(() => startOfMonth(new Date()));
  const [scope, setScope] = useState<ClCalendarScope>('mine');
  const [selectedKey, setSelectedKey] = useState(() =>
    clLocalDateKey(new Date()),
  );

  const tours = useListClToursQuery({ page: 1, limit: CL_CALENDAR_FETCH_LIMIT });
  const visits = useListClVisitsQuery({ page: 1, limit: CL_CALENDAR_FETCH_LIMIT });
  // Tour rows show the family's name, not a uuid — same lookup the tour list does.
  const leads = useListClLeadsQuery({ page: 1, limit: CL_CALENDAR_FETCH_LIMIT });

  const leadName = useMemo(() => {
    const map = new Map(
      (leads.data?.data ?? []).map((lead) => [
        lead.id,
        [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() ||
          'Lead',
      ]),
    );
    return (id: string | null) => (id ? (map.get(id) ?? 'Lead') : 'No lead');
  }, [leads.data]);

  const allEvents = useMemo<ClCalendarEvent[]>(
    () => [
      ...(tours.data?.data ?? []).map((tour) =>
        tourToEvent(tour, leadName(tour.leadId)),
      ),
      ...(visits.data?.data ?? []).map(visitToEvent),
    ],
    [tours.data, visits.data, leadName],
  );

  const hasUnownedEvents = useMemo(
    () => allEvents.some((event) => event.ownerId === null),
    [allEvents],
  );

  const events = useMemo(() => {
    if (scope === 'all') return allEvents;
    // Owner-less rows (an unassigned tour) are kept, so they are not invisible
    // to everyone at once — see the scope caveat above. Visits now carry a real
    // owner, so they are filtered like any other row.
    return allEvents.filter(
      (event) => event.ownerId === null || event.ownerId === userId,
    );
  }, [allEvents, scope, userId]);

  const cells = useMemo(() => buildClMonthGrid(month, events), [month, events]);

  const selectedEvents = useMemo(
    () => cells.find((cell) => cell.key === selectedKey)?.items ?? [],
    [cells, selectedKey],
  );

  return {
    month,
    cells,
    scope,
    setScope,
    selectedKey,
    selectDay: setSelectedKey,
    selectedEvents,
    prevMonth: () =>
      setMonth((m) => new Date(m.getFullYear(), m.getMonth() - 1, 1)),
    nextMonth: () =>
      setMonth((m) => new Date(m.getFullYear(), m.getMonth() + 1, 1)),
    goToday: () => {
      const now = new Date();
      setMonth(startOfMonth(now));
      setSelectedKey(clLocalDateKey(now));
    },
    hasUnownedEvents,
    isLoading: tours.isLoading || visits.isLoading,
    isFetching: tours.isFetching || visits.isFetching,
    isError: tours.isError || visits.isError,
  };
}
