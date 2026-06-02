import { Calendar, ScrollText, Pin, Goal } from 'lucide-react';
import type { ActivityUiState, DailyGoal } from '../types/activityTypes';

export const ACTIVITY_TABS: ReadonlyArray<{
  value: ActivityUiState['activeTab'];
  label: string;
  icon: typeof Calendar;
}> = [
  { value: 'calendar', label: 'Calendar', icon: Calendar },
  { value: 'notes', label: 'Notes', icon: ScrollText },
  { value: 'reminders', label: 'Reminders', icon: Pin },
  { value: 'goals', label: 'Daily goals', icon: Goal },
];

export const ACTIVITY_DAILY_GOALS: readonly DailyGoal[] = [
  { id: 'visits', label: 'Facility visits', current: 4, target: 6 },
  { id: 'calls', label: 'Phone calls', current: 9, target: 12 },
  { id: 'prospects', label: 'New prospects', current: 2, target: 3 },
];

export const REMINDER_BUCKETS = ['overdue', 'today', 'this_week'] as const;

export const REMINDER_BUCKET_LABELS: Record<
  (typeof REMINDER_BUCKETS)[number],
  string
> = {
  overdue: 'Overdue',
  today: 'Due today',
  this_week: 'This week',
};

export const REMINDER_BUCKET_TONE: Record<
  (typeof REMINDER_BUCKETS)[number],
  string
> = {
  overdue: 'border-destructive/30 bg-destructive/10 text-destructive',
  today: 'border-warning/30 bg-warning/10 text-warning',
  this_week: 'border-azure/30 bg-azure/10 text-azure',
};
