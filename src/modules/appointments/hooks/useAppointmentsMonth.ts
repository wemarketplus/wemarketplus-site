import { useCallback, useMemo, useState } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useGetCalendarQuery } from '../api/appointmentsApi';
import type { CalendarScope } from './useAppointmentsCalendar';
import {
  buildMonthGrid,
  localDateKey,
  monthWindow,
} from '../utils/appointmentsUtils';

/**
 * Month-grid calendar state. The feed window follows the visible grid (including
 * the leading/trailing days of adjacent months), so a visit on a spillover day
 * still shows up in its cell.
 *
 * `scope` exists because this view had no scope at all: it was unconditionally
 * tenant-wide while the agenda defaulted to "My calendar", and the month grid is
 * where the page opens. So a Caregiver following the product guide's "use Calendar
 * (My Calendar view) to see your scheduled visits" landed on six colleagues'
 * appointments — marketing lunch-and-learns included — with no control on screen
 * to narrow it, and had to discover the Agenda tab to find the toggle.
 */
export function useAppointmentsMonth(scope: CalendarScope = 'mine') {
  const [month, setMonth] = useState(() => {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), 1);
  });
  const [selectedKey, setSelectedKey] = useState<string | null>(() =>
    localDateKey(new Date()),
  );

  const window = useMemo(() => monthWindow(month), [month]);
  const myUserId = useAppSelector((s) => s.auth.user?.id ?? null);
  // Server-side via `assignedRep`, matching useAppointmentsCalendar: the feed is
  // capped at CALENDAR_MAX_RESULTS, so filtering the response instead would
  // silently drop your own visits that fell past the cap on a busy tenant.
  const { data, isLoading, isFetching, isError } = useGetCalendarQuery({
    ...window,
    ...(scope === 'mine' && myUserId ? { assignedRep: myUserId } : {}),
  });
  const appointments = useMemo(() => data ?? [], [data]);

  const cells = useMemo(
    () => buildMonthGrid(month, appointments),
    [month, appointments],
  );

  const shiftMonth = useCallback((delta: number) => {
    setMonth((current) => {
      const next = new Date(current);
      // Day is pinned to 1 by construction, so month arithmetic can't overflow
      // (e.g. Jan 31 + 1 month landing in March).
      next.setMonth(next.getMonth() + delta);
      return next;
    });
  }, []);

  const goToday = useCallback(() => {
    const now = new Date();
    setMonth(new Date(now.getFullYear(), now.getMonth(), 1));
    setSelectedKey(localDateKey(now));
  }, []);

  const selectedDay = useMemo(
    () => cells.find((cell) => cell.key === selectedKey) ?? null,
    [cells, selectedKey],
  );

  return {
    month,
    cells,
    appointments,
    selectedKey,
    selectedDay,
    selectDay: setSelectedKey,
    prevMonth: () => shiftMonth(-1),
    nextMonth: () => shiftMonth(1),
    goToday,
    isLoading,
    isFetching,
    isError,
  };
}
