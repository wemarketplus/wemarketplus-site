import { useMemo } from 'react';
import { useFollowUps } from './useFollowUps';

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
 * The Follow-ups tab: the follow-ups this user owes, soonest first.
 *
 * IT USED TO READ THE APPOINTMENTS FEED — the same visits the Calendar screen shows.
 * A tab headed "Upcoming follow-ups", sitting next to a Calendar tab, listed
 * scheduled visits and never the follow-ups themselves: a nurse who logged a family
 * call with a "Follow up on" date got a reminder created server-side and then read
 * "No upcoming follow-ups" here. Two rows showing one feed while the thing they were
 * named for had no home at all.
 *
 * The CalendarEvent shape is unchanged so CalendarView renders as before; only the
 * source moved. `nextStep` now carries the follow-up's own detail (the note's next
 * step, which is what NotesService copies into the reminder) and the patient it is
 * about, which is the pair a nurse needs to act without opening anything.
 */
export function useCalendarEvents(): UseCalendarEventsResult {
  const { followUps, isLoading, isError } = useFollowUps();

  const events = useMemo<readonly CalendarEvent[]>(
    () =>
      followUps.map((followUp) => ({
        id: followUp.id,
        name: followUp.patientName
          ? `${followUp.title} · ${followUp.patientName}`
          : followUp.title,
        nextStep: followUp.detail ?? '',
        followUpDate: followUp.dueDate,
      })),
    [followUps],
  );

  return {
    events,
    isEmpty: events.length === 0,
    isLoading,
    isError,
    // The feed has no separate background-refresh state to expose; callers that
    // showed a subtle "updating" hint can keep reading this without branching.
    isFetching: isLoading,
  };
}
