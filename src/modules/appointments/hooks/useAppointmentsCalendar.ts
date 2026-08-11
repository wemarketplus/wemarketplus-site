import { useMemo, useState } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useGetCalendarQuery } from '../api/appointmentsApi';
import { defaultCalendarWindow, groupByDay } from '../utils/appointmentsUtils';

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
  } = {},
) {
  const [ownScope, setOwnScope] = useState<CalendarScope>('mine');
  const scope = options.scope ?? ownScope;
  const setScope = setOwnScope;
  const window = options.window ?? defaultCalendarWindow();
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
  const appointments = useMemo(() => data ?? [], [data]);
  const days = useMemo(() => groupByDay(appointments), [appointments]);

  return {
    appointments,
    days,
    isEmpty: appointments.length === 0,
    isLoading,
    isFetching,
    isError,
    scope,
    setScope,
    myUserId,
  };
}
