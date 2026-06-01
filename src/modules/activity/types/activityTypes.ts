import type { ProspectNote, Reminder } from '@/shared/types';

export type { ProspectNote, Reminder };

export interface DailyGoal {
  id: string;
  label: string;
  current: number;
  target: number;
}

export interface ActivityUiState {
  // Activity tab on the page (calendar, notes, reminders, goals).
  activeTab: 'calendar' | 'notes' | 'reminders' | 'goals';
}
