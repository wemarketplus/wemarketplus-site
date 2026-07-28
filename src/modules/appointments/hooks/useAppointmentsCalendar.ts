import { useMemo } from 'react';
import { useGetCalendarQuery } from '../api/appointmentsApi';
import { defaultCalendarWindow, groupByDay } from '../utils/appointmentsUtils';

/**
 * The real calendar feed. This replaces the previous fake, which mapped
 * `prospects.updatedAt` because no appointments table existed.
 */
export function useAppointmentsCalendar(window = defaultCalendarWindow()) {
  const { data, isLoading, isFetching, isError } = useGetCalendarQuery(window);

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
  };
}
