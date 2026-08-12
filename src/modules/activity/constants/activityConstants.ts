import { ACTIVITY_TYPE_OPTIONS } from '@/shared/constants/activityTypeConstants';
import { Calendar, ScrollText, Pin, Goal } from 'lucide-react';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import { Urgency } from '@/shared/types';
import { TaskPriority, TaskStatus } from '../types/activityTypes';
import type { ActivityUiState, DailyGoal } from '../types/activityTypes';
import type { NoteFormValues } from '../schema/noteSchema';
import type { TaskFormValues } from '../schema/taskSchema';
import type { GoalFormValues } from '../schema/goalSchema';

/**
 * Page size for the follow-up feed (`GET /tasks`), which backs both the Follow-ups
 * tab and the follow-up markers on the month calendar.
 *
 * MAX_LIMIT on the backend is 100, so this is the most one request can ask for —
 * not a number chosen for comfort. The default was 20, which silently truncated the
 * list; if a user ever holds more than 100 open follow-ups the feed needs a date
 * window (`GET /tasks` has only `dueOnOrBefore` today), not a bigger page.
 */
export const FOLLOW_UP_FEED_LIMIT = 100;

export const ACTIVITY_TABS: ReadonlyArray<{
  value: ActivityUiState['activeTab'];
  label: string;
  icon: typeof Calendar;
}> = [
  // "Follow-ups", matching the renamed sidebar row. This tab lists upcoming
  // follow-up dates — it is not the calendar, and the guide's "Calendar" is now
  // the Appointments screen (month grid, My calendar / All users, per-user
  // colours). Two rows called Calendar is what sent people to the wrong one.
  { value: 'calendar', label: 'Follow-ups', icon: Calendar },
  // "Notes & team notes", matching the sidebar row: this tab IS the team-notes
  // surface for clinical staff, who cannot reach the copy inside the prospect
  // drawer (Prospects is marketing-only). A tab labelled just "Notes" read as a
  // private scratchpad, which is the opposite of what the list is.
  { value: 'notes', label: 'Notes & team notes', icon: ScrollText },
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

/**
 * A goal either counts something the CRM already records, or it is a number
 * somebody types. The manual option is named "Manual entry" rather than "None"
 * so it is clear that progress will not move on its own.
 */
const GOAL_METRIC_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'manual', label: 'Manual entry' },
  { value: 'visits', label: 'Visits (completed appointments)' },
  { value: 'calls', label: 'Calls (notes logged as a phone call)' },
  { value: 'referrals', label: 'Referrals (prospects assigned to you)' },
];

const GOAL_PERIOD_OPTIONS: readonly EntitySelectOption[] = [
  { value: 'daily', label: 'Daily' },
  { value: 'weekly', label: 'Weekly' },
  { value: 'monthly', label: 'Monthly' },
  { value: 'quarterly', label: 'Quarterly' },
  { value: 'yearly', label: 'Yearly' },
];

// Notes: a note targets a prospect, a referral source or a contact — at least
// one, possibly several (FIX-1). All three are pickers, never typed: they were
// once free-text "paste the UUID" boxes, which no end user could fill.
// `activityType` replaces the old free-text "contact type": one canonical enum
// shared with appointments, so a brochure drop-off and a lunch-and-learn are
// finally distinguishable in the log (FIX-3).
//
// `isFamilySensitive` is deliberately absent from this list: it is a checkbox,
// which the field-descriptor grid has no type for, so NoteFormModal renders it in
// the footerNote slot rather than every other module's form gaining a field type
// it does not use.
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
  {
    name: 'metric',
    label: 'Track automatically',
    type: 'select',
    options: GOAL_METRIC_OPTIONS,
  },
];
