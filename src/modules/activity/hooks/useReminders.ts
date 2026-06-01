import { useMemo } from 'react';
import { REMINDERS_FIXTURE } from '@/shared/fixtures';
import { bucketReminders } from '../utils/activityUtils';

// Reminder list is fixture-only today. Replace `REMINDERS_FIXTURE` with an
// RTK Query result once /reminders ships.
export function useReminders() {
  const reminders = REMINDERS_FIXTURE;
  const buckets = useMemo(() => bucketReminders(reminders), [reminders]);
  const overdueCount = buckets.overdue.length;
  return { reminders, buckets, overdueCount, isUsingFixture: true };
}
