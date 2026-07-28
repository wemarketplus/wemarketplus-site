import { useMemo } from 'react';
import { useAppointmentsCalendar } from '@/modules/appointments';
import {
  APPOINTMENT_TYPE_LABELS,
} from '@/modules/appointments/constants/appointmentsConstants';

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

/**
 * Upcoming follow-ups for the activity calendar.
 *
 * This now reads the REAL appointments feed (GET /hl/appointments/calendar). It
 * previously derived pseudo-events from `prospects.updatedAt` because no
 * appointments table existed — that fake is gone. The CalendarEvent shape is kept
 * so CalendarView renders unchanged.
 */
export function useCalendarEvents(): UseCalendarEventsResult {
  const { appointments, isLoading, isFetching, isError } =
    useAppointmentsCalendar();

  const events = useMemo<readonly CalendarEvent[]>(
    () =>
      appointments.map((appointment) => ({
        id: appointment.id,
        name: appointment.title,
        nextStep: [
          APPOINTMENT_TYPE_LABELS[appointment.appointmentType],
          appointment.location,
        ]
          .filter(Boolean)
          .join(' · '),
        followUpDate: appointment.startAt,
      })),
    [appointments],
  );

  return {
    events,
    isEmpty: events.length === 0,
    isLoading,
    isError,
    isFetching,
  };
}
