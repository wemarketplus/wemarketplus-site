import { useCallback, useMemo, useState } from 'react';
import { useGetCalendarQuery } from '../api/appointmentsApi';
import {
  buildMonthGrid,
  localDateKey,
  monthWindow,
} from '../utils/appointmentsUtils';

/**
 * Month-grid calendar state. The feed window follows the visible grid (including
 * the leading/trailing days of adjacent months), so a visit on a spillover day
 * still shows up in its cell.
 */
export function useAppointmentsMonth() {
  const [month, setMonth] = useState(() => {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), 1);
  });
  const [selectedKey, setSelectedKey] = useState<string | null>(() =>
    localDateKey(new Date()),
  );

  const window = useMemo(() => monthWindow(month), [month]);
  const { data, isLoading, isFetching, isError } = useGetCalendarQuery(window);
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
