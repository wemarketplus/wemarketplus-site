import {
  ACTIVITY_TYPE_LABELS,
  ACTIVITY_TYPE_REQUIRING_DETAIL,
} from '@/shared/constants/activityTypeConstants';
import type { Reminder } from '@/shared/types';
import { REMINDER_BUCKETS } from '../constants/activityConstants';
import type { NoteRecord } from '../types/activityTypes';

/**
 * What kind of interaction a note records, as display text.
 *
 * `other` carries its own free text — that is the whole reason the backend makes
 * it mandatory — so show that instead of the word "Other". Older rows have no
 * `activityType` at all and yield '', which callers render as nothing rather than
 * as an empty label.
 *
 * Shared by the touch log and the Notes screen so one note describes itself the
 * same way on both.
 */
export function activityTypeLabel(
  note: Pick<NoteRecord, 'activityType' | 'activityTypeOther'>,
): string {
  if (!note.activityType) return '';
  if (note.activityType === ACTIVITY_TYPE_REQUIRING_DETAIL) {
    return note.activityTypeOther || ACTIVITY_TYPE_LABELS[note.activityType];
  }
  return ACTIVITY_TYPE_LABELS[note.activityType];
}

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

/**
 * Is this follow-up date already past? Compared as a CALENDAR DAY, not an instant.
 *
 * The old form was `new Date(followUpDate) < Date.now()`, and a `YYYY-MM-DD` string
 * parses as UTC midnight — so anything due TODAY read as overdue from 00:01 local
 * onward (and, for readers east of UTC, a date due tomorrow could too). Comparing
 * the day strings makes "due today" simply due, which is what a nurse looking at
 * today's follow-up expects to see.
 */
export function isEventOverdue(followUpDate: string, now = new Date()): boolean {
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  // Tolerates a full ISO timestamp as well as a date-only string.
  return followUpDate.slice(0, 10) < today;
}

export function computeGoalProgress(
  current: number,
  target: number,
): { pct: number; hit: boolean } {
  return {
    pct: Math.min(100, Math.round((current / target) * 100)),
    hit: current >= target,
  };
}
