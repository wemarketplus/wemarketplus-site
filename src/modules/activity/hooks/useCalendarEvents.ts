import { useMemo } from 'react';
import { useListProspectsQuery } from '@/modules/prospects/api/prospectsApi';

export interface CalendarEvent {
  id: string;
  name: string;
  nextStep: string;
  followUpDate: string;
}

export interface UseCalendarEventsResult {
  events: readonly CalendarEvent[];
  isEmpty: boolean;
  isLoading: boolean;
  isError: boolean;
  isFetching: boolean;
}

export function useCalendarEvents(): UseCalendarEventsResult {
  const { data, isLoading, isError, isFetching } = useListProspectsQuery();

  const events = useMemo<readonly CalendarEvent[]>(() => {
    const records = data?.data ?? [];
    return records
      .map((p) => ({
        id: p.id,
        name: p.patientName,
        nextStep: p.stage,
        followUpDate: p.updatedAt,
      }))
      .sort(
        (a, b) =>
          new Date(a.followUpDate).getTime() -
          new Date(b.followUpDate).getTime(),
      );
  }, [data]);

  return {
    events,
    isEmpty: events.length === 0,
    isLoading,
    isError,
    isFetching,
  };
}
