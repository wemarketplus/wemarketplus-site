import { useMemo } from 'react';
import { REMINDERS_FIXTURE } from '@/shared/fixtures';
import type { Reminder } from '@/shared/types';
import { useListTasksQuery } from '../api/activityApi';
import { TaskStatus } from '../types/activityTypes';
import { toReminder } from '../utils/activityMappers';
import { bucketReminders } from '../utils/activityUtils';

export function useReminders() {
  const { data } = useListTasksQuery();

  const reminders = useMemo<readonly Reminder[]>(() => {
    if (!data) return REMINDERS_FIXTURE;
    return data.data
      .filter((t) => t.dueDate && t.status !== TaskStatus.Completed && t.status !== TaskStatus.Cancelled)
      .map(toReminder);
  }, [data]);

  const buckets = useMemo(() => bucketReminders(reminders), [reminders]);
  const overdueCount = buckets.overdue.length;

  return { reminders, buckets, overdueCount, isUsingFixture: !data };
}
