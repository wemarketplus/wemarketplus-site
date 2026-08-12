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
   * True when the current scope is hiding nothing it claims to hide — i.e.
   * whether "My calendar" is trustworthy. False while unowned visits are present,
   * so the UI can say so. See the ownership note below.
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
 * only filter records that say who owns them. Tours do (`guideUserId`); outreach
 * visits do NOT — their DTO carries no user field at all — so unowned visits stay
 * visible in BOTH scopes rather than vanishing from a marketer's own calendar or
 * being falsely attributed to them. `hasUnownedEvents` lets the scope toggle
 * admit this. The fix is a `createdBy`/`userId` field on cl/outreach-visits.
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
    // Unowned rows are kept — see the scope caveat above.
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
