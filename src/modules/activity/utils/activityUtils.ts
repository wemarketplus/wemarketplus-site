import type { Reminder } from '@/shared/types';
import { REMINDER_BUCKETS } from '../constants/activityConstants';

export function bucketReminders(
  reminders: readonly Reminder[],
): Record<(typeof REMINDER_BUCKETS)[number], Reminder[]> {
  const buckets: Record<string, Reminder[]> = {
    overdue: [],
    today: [],
    this_week: [],
  };
  for (const r of reminders) buckets[r.dueStatus]?.push(r);
  return buckets as Record<(typeof REMINDER_BUCKETS)[number], Reminder[]>;
}
