import { useMemo, useState } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useGetCalendarQuery } from '../api/appointmentsApi';
import { CALENDAR_PAST_DUE_LOOKBACK_DAYS } from '../constants/appointmentsConstants';
import {
  defaultCalendarWindow,
  groupByDay,
  isOnOpenAgenda,
  isPastDue,
} from '../utils/appointmentsUtils';

/** Whose appointments the calendar shows. */
export type CalendarScope = 'mine' | 'all';

/**
 * The real calendar feed. This replaces the previous fake, which mapped
 * `prospects.updatedAt` because no appointments table existed.
 */
export function useAppointmentsCalendar(
  options: {
    /**
     * Scope supplied by the caller, making this hook CONTROLLED. AppointmentsPage
     * passes it so the month grid and the agenda share one My calendar / All users
     * choice instead of each owning a separate copy — switching views used to
     * silently change whose calendar you were looking at. Omitted (the Follow-ups
     * screen) the hook keeps its own state and behaves exactly as before.
     */
    scope?: CalendarScope;
    window?: ReturnType<typeof defaultCalendarWindow>;
    /**
     * Carry still-open visits from the last CALENDAR_PAST_DUE_LOOKBACK_DAYS into the
     * agenda instead of starting hard at today.
     *
     * OPT-IN rather than the default: the Calendar screen's agenda is "my visits —
     * what's next and what I still owe", where a missed visit is the single most
     * important row on the list. The Follow-ups screen renders the same feed under
     * the heading "upcoming", so it stays forward-only.
     */
    includeOverdue?: boolean;
  } = {},
) {
  const [ownScope, setOwnScope] = useState<CalendarScope>('mine');
  const scope = options.scope ?? ownScope;
  const setScope = setOwnScope;
  const includeOverdue = options.includeOverdue ?? false;
  const window =
    options.window ??
    defaultCalendarWindow(
      undefined,
      includeOverdue ? CALENDAR_PAST_DUE_LOOKBACK_DAYS : 0,
    );
  const myUserId = useAppSelector((s) => s.auth.user?.id ?? null);

  // Scoping is done SERVER-side via the existing `assignedRep` filter rather
  // than by filtering the response: the feed is capped at CALENDAR_MAX_RESULTS,
  // so a client-side filter on a busy tenant would silently drop a rep's own
  // visits that fell past the cap.
  const { data, isLoading, isFetching, isError } = useGetCalendarQuery({
    ...window,
    ...(scope === 'mine' && myUserId ? { assignedRep: myUserId } : {}),
  });

  // Memoised so the `?? []` fallback does not produce a new array identity every
  // render, which would re-run the grouping (and any consumer's effects) needlessly.
  //
  // The lookback widens the REQUEST, so it also returns visits that were finished or
  // cancelled in those days. Those are history, not agenda: dropping them here keeps
  // the list "what's next plus what I still owe" rather than a scroll of last
  // fortnight's completed work.
  const appointments = useMemo(() => {
    const rows = data ?? [];
    return includeOverdue ? rows.filter((row) => isOnOpenAgenda(row)) : rows;
  }, [data, includeOverdue]);
  const days = useMemo(() => groupByDay(appointments), [appointments]);
  const overdueCount = useMemo(
    () => appointments.filter((row) => isPastDue(row)).length,
    [appointments],
  );

  return {
    appointments,
    days,
    overdueCount,
    isEmpty: appointments.length === 0,
    isLoading,
    isFetching,
    isError,
    scope,
    setScope,
    myUserId,
  };
}
