import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { useListTasksQuery } from '../api/activityApi';
import { FOLLOW_UP_FEED_LIMIT } from '../constants/activityConstants';
import { TaskStatus } from '../types/activityTypes';
import { useNotePatientOptions } from './useNoteLookups';

/**
 * One outstanding follow-up, ready to render on a list or a calendar cell.
 *
 * `dueDate` stays the raw `YYYY-MM-DD` the API returns and is NEVER put through
 * `new Date()` on the way to a calendar key: a date-only string parses as UTC
 * midnight, so west-of-UTC readers would see every follow-up land a day early.
 */
export interface FollowUpItem {
  id: string;
  title: string;
  detail: string | null;
  /** `YYYY-MM-DD`, matching the month grid's cell keys exactly. */
  dueDate: string;
  /** Null when the follow-up is not about a patient, or the patient is not visible. */
  patientName: string | null;
}

/**
 * The caller's outstanding follow-ups — the reminders that a dated note creates.
 *
 * WHY THIS EXISTS: logging a family contact with a "Follow up on" date creates a
 * reminder server-side (NotesService.ensureFollowUpReminder → TasksService), and
 * that reminder appeared ONLY on the Reminders tab. The screen titled "Upcoming
 * follow-ups" rendered the APPOINTMENTS feed instead, so a nurse who logged a call
 * and promised to ring the family back on Thursday saw "No upcoming follow-ups" and
 * nothing on the calendar. This is the shared source for both surfaces, so they can
 * never disagree again.
 *
 * Completed and cancelled work is dropped, and undated reminders with it: a
 * follow-up with no date cannot be placed on a calendar, and the Reminders tab is
 * where those live.
 *
 * `selfOnly` passes `assignedTo` explicitly. It is not redundant: the backend forces
 * `assignedTo = caller` for ordinary roles, but an oversight role (SuperAdmin /
 * Admin / Owner) gets the tenant-wide list, and on a calendar switched to "My
 * calendar" that would show a manager their whole team's follow-ups.
 */
export function useFollowUps(selfOnly = true): {
  followUps: readonly FollowUpItem[];
  isLoading: boolean;
  isError: boolean;
} {
  const myUserId = useAppSelector((s) => s.auth.user?.id ?? null);
  const { data, isLoading, isError } = useListTasksQuery({
    limit: FOLLOW_UP_FEED_LIMIT,
    ...(selfOnly && myUserId ? { assignedTo: myUserId } : {}),
  });

  // Resolves the patient a follow-up is about. Same role-aware source the note
  // pickers use, so a clinician sees the patient directory and a marketer the
  // pipeline — and neither is shown a name their role may not read.
  const patients = useNotePatientOptions(true);
  const patientNames = useMemo(
    () => new Map((patients ?? []).map((option) => [option.value, option.label])),
    [patients],
  );

  const followUps = useMemo<readonly FollowUpItem[]>(
    () =>
      (data?.data ?? [])
        .filter(
          (task) =>
            task.dueDate &&
            task.status !== TaskStatus.Completed &&
            task.status !== TaskStatus.Cancelled,
        )
        .map((task) => ({
          id: task.id,
          title: task.title,
          detail: task.description,
          dueDate: task.dueDate as string,
          patientName: task.prospectId
            ? (patientNames.get(task.prospectId) ?? null)
            : null,
        }))
        // Soonest first, and string compare is correct for ISO dates.
        .sort((a, b) => a.dueDate.localeCompare(b.dueDate)),
    [data, patientNames],
  );

  return { followUps, isLoading, isError };
}
