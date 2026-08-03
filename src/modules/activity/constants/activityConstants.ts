import { ACTIVITY_TYPE_OPTIONS } from '@/shared/constants/activityTypeConstants';
import { Calendar, ScrollText, Pin, Goal } from 'lucide-react';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import { Urgency } from '@/shared/types';
import { TaskPriority, TaskStatus } from '../types/activityTypes';
import type { ActivityUiState, DailyGoal } from '../types/activityTypes';
import type { NoteFormValues } from '../schema/noteSchema';
import type { TaskFormValues } from '../schema/taskSchema';
import type { GoalFormValues } from '../schema/goalSchema';

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

// --- Create/edit form option lists + field descriptors ---------------------

const URGENCY_OPTIONS: readonly EntitySelectOption[] = [
  { value: Urgency.Hot, label: 'Hot' },
  { value: Urgency.Warm, label: 'Warm' },
  { value: Urgency.Cold, label: 'Cold' },
];

const TASK_PRIORITY_OPTIONS: readonly EntitySelectOption[] = [
  { value: TaskPriority.Urgent, label: 'Urgent' },
  { value: TaskPriority.High, label: 'High' },
  { value: TaskPriority.Medium, label: 'Medium' },
  { value: TaskPriority.Low, label: 'Low' },
];

const TASK_STATUS_OPTIONS: readonly EntitySelectOption[] = [
  { value: TaskStatus.Pending, label: 'Pending' },
  { value: TaskStatus.InProgress, label: 'In progress' },
  { value: TaskStatus.Completed, label: 'Completed' },
  { value: TaskStatus.Cancelled, label: 'Cancelled' },
];

const GOAL_PERIOD_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
  { value: 'quarterly', label: 'Quarterly' },
  { value: 'yearly', label: 'Yearly' },
];

// Notes: prospectId is a raw UUID field (the reminders/notes tabs do not yet
// have a prospect picker, so it is entered directly).
// A note now targets a prospect, a referral source or a contact — at least one,
// possibly several (FIX-1). `activityType` replaces the old free-text
// "contact type": one canonical enum shared with appointments, so a brochure
// drop-off and a lunch-and-learn are finally distinguishable in the log (FIX-3).
/** Activity-type options with a leading blank, since the field is optional. */
const ACTIVITY_TYPE_SELECT_OPTIONS = [
  { value: '', label: 'Not recorded' },
  ...ACTIVITY_TYPE_OPTIONS,
];

export const NOTE_FIELDS: ReadonlyArray<EntityField<NoteFormValues>> = [
  // Record references, chosen from a list — never typed. Options are supplied at
  // render time by NoteFormModal via EntityFormModal's `lookups` prop.
  { name: 'prospectId', label: 'Prospect', type: 'lookup', placeholder: 'No prospect' },
  { name: 'referralSourceId', label: 'Referral source', type: 'lookup', placeholder: 'No referral source' },
  { name: 'contactId', label: 'Contact', type: 'lookup', placeholder: 'No contact' },
  { name: 'summary', label: 'Summary', type: 'textarea', full: true, placeholder: 'What happened on this interaction…' },
  { name: 'activityType', label: 'Activity type', type: 'select', options: ACTIVITY_TYPE_SELECT_OPTIONS },
  { name: 'activityTypeOther', label: 'If “other”, describe it', placeholder: 'Required when the type is other' },
  { name: 'urgency', label: 'Urgency', type: 'select', options: URGENCY_OPTIONS },
  { name: 'patientStatus', label: 'Status', placeholder: 'Current status' },
  { name: 'followUpDate', label: 'Follow-up date', type: 'date' },
  { name: 'barriers', label: 'Barriers', type: 'textarea', full: true, placeholder: 'Obstacles to conversion…' },
  { name: 'nextStep', label: 'Next step', type: 'textarea', full: true, placeholder: 'What to do next…' },
];

export const TASK_FIELDS: ReadonlyArray<EntityField<TaskFormValues>> = [
  { name: 'title', label: 'Title', full: true, placeholder: 'Follow up with prospect' },
  { name: 'description', label: 'Description', type: 'textarea', full: true, placeholder: 'Details…' },
  { name: 'dueDate', label: 'Due date', type: 'date' },
  { name: 'priority', label: 'Priority', type: 'select', options: TASK_PRIORITY_OPTIONS },
  { name: 'status', label: 'Status', type: 'select', options: TASK_STATUS_OPTIONS },
];

export const GOAL_FIELDS: ReadonlyArray<EntityField<GoalFormValues>> = [
  { name: 'title', label: 'Title', full: true, placeholder: 'Facility visits' },
  { name: 'targetValue', label: 'Target', type: 'number', placeholder: '6' },
  { name: 'currentValue', label: 'Current', type: 'number', placeholder: '0' },
  { name: 'unit', label: 'Unit', placeholder: 'count, visits, calls…' },
  { name: 'period', label: 'Period', type: 'select', options: GOAL_PERIOD_OPTIONS },
];
