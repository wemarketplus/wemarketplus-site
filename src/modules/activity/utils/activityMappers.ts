import { displayName, type NameTable } from '@/shared/hooks';
import { opt } from '@/shared/ui/entity';
import type {
  CreateGoalRequest,
  CreateNoteRequest,
  CreateTaskRequest,
  DailyGoal,
  GoalPeriod,
  GoalRecord,
  NoteRecord,
  TaskPriority,
  TaskRecord,
  TaskStatus,
  UpdateGoalRequest,
  UpdateNoteRequest,
  UpdateTaskRequest,
} from '../types/activityTypes';
import type { GoalFormValues } from '../schema/goalSchema';
import type { NoteFormValues } from '../schema/noteSchema';
import type { TaskFormValues } from '../schema/taskSchema';
import type { ProspectNote, Reminder, Urgency } from '@/shared/types';

// Pure mappers from backend records onto the activity-page view-models.
// Kept in utils/ so the hooks stay orchestration-only.

export function toDailyGoal(g: GoalRecord): DailyGoal {
  return {
    id: g.id,
    label: g.title,
    // Postgres numeric columns arrive as strings via TypeORM; coerce so the
    // progress math (computeGoalProgress) operates on real numbers.
    current: Number(g.currentValue),
    target: Number(g.targetValue),
    // Carried through so the card can show WHERE the number came from. A tracked
    // goal's progress is derived from logged visits/calls/referrals; presenting
    // it identically to a hand-typed one would invite someone to "correct" it.
    isTracked: g.isTracked,
    today: g.todayValue,
    weekToDate: g.weekToDateValue,
  };
}

// The backend NoteResponseDto doesn't store position/interactionType, so those
// render blank until the read model exposes them.
//
// `author` is resolved from `createdBy`, which is a USER ID. It used to be
// rendered as-is, which put a bare uuid where the note's author name belongs.
// `displayName` yields '' for an id it cannot resolve — never the id.
export function toProspectNote(
  n: NoteRecord,
  userNames?: NameTable,
): ProspectNote {
  return {
    id: n.id,
    // Nullable since FIX-1 — a note may target an account or a person instead of
    // a prospect. The legacy ProspectNote shape has no room for that, so an
    // account-scoped note renders with an empty prospectId here.
    prospectId: n.prospectId ?? '',
    author: displayName(userNames, n.createdBy),
    position: '',
    interactionType: n.contactType ?? '',
    contactType: n.contactType ?? '',
    urgency: n.urgency as Urgency,
    date: n.createdAt,
    summary: n.summary,
    patientStatus: n.patientStatus ?? undefined,
    barriers: n.barriers ?? undefined,
    nextStep: n.nextStep ?? '',
    assignedTo: n.assignedTo ?? '',
    followUpDate: n.followUpDate ?? n.createdAt,
    gpsLocation: n.gpsLocation ?? undefined,
  };
}

// Tasks with a due date act as the reminder feed; derive the bucket from the
// due date relative to today.
function dueStatus(dueDate: string): Reminder['dueStatus'] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const due = new Date(dueDate);
  due.setHours(0, 0, 0, 0);
  const diffDays = Math.round((due.getTime() - today.getTime()) / 86_400_000);
  if (diffDays < 0) return 'overdue';
  if (diffDays === 0) return 'today';
  return 'this_week';
}

export function toReminder(t: TaskRecord): Reminder {
  return {
    id: t.id,
    sourceName: t.title,
    actionDescription: t.description ?? t.title,
    dueStatus: dueStatus(t.dueDate as string),
    dueDate: t.dueDate as string,
    marketerId: t.assignedTo ?? '',
  };
}

// --- Form <-> DTO mappers (create/edit) ------------------------------------
// `opt`/`optNum` drop blank optionals so the backend's whitelist + Matches(ISO)
// rules never receive an empty string.

// Notes -----------------------------------------------------------------
export function toCreateNote(v: NoteFormValues): CreateNoteRequest {
  return {
    summary: v.summary.trim(),
    urgency: v.urgency,
    // At least one of these three is guaranteed by noteSchema's refinement.
    ...opt('prospectId', v.prospectId),
    ...opt('referralSourceId', v.referralSourceId),
    ...opt('contactId', v.contactId),
    ...opt('activityType', v.activityType),
    ...opt('activityTypeOther', v.activityTypeOther),
    ...opt('contactType', v.contactType),
    ...opt('patientStatus', v.patientStatus),
    ...opt('barriers', v.barriers),
    ...opt('nextStep', v.nextStep),
    ...opt('followUpDate', v.followUpDate),
  };
}

// Backend UpdateNoteDto excludes all three target ids — a note cannot be
// re-linked once written.
export function toUpdateNote(v: NoteFormValues): UpdateNoteRequest {
  const {
    prospectId: _prospectId,
    referralSourceId: _referralSourceId,
    contactId: _contactId,
    ...rest
  } = toCreateNote(v);
  return rest;
}

export function toNoteFormValues(n: NoteRecord): NoteFormValues {
  return {
    prospectId: n.prospectId ?? '',
    referralSourceId: n.referralSourceId ?? '',
    contactId: n.contactId ?? '',
    summary: n.summary,
    activityType: n.activityType ?? '',
    activityTypeOther: n.activityTypeOther ?? '',
    contactType: n.contactType ?? '',
    urgency: n.urgency,
    patientStatus: n.patientStatus ?? '',
    barriers: n.barriers ?? '',
    nextStep: n.nextStep ?? '',
    followUpDate: n.followUpDate ?? '',
  };
}

// Tasks -----------------------------------------------------------------
export function toCreateTask(v: TaskFormValues): CreateTaskRequest {
  return {
    title: v.title.trim(),
    priority: v.priority as TaskPriority,
    status: v.status as TaskStatus,
    ...opt('description', v.description),
    ...opt('dueDate', v.dueDate),
  };
}

export function toUpdateTask(v: TaskFormValues): UpdateTaskRequest {
  return toCreateTask(v);
}

export function toTaskFormValues(t: TaskRecord): TaskFormValues {
  return {
    title: t.title,
    description: t.description ?? '',
    dueDate: t.dueDate ?? '',
    priority: t.priority,
    status: t.status,
  };
}

// Goals -----------------------------------------------------------------
export function toCreateGoal(v: GoalFormValues): CreateGoalRequest {
  return {
    title: v.title.trim(),
    targetValue: v.targetValue,
    currentValue: v.currentValue,
    period: v.period as GoalPeriod,
    ...opt('unit', v.unit),
  };
}

export function toUpdateGoal(v: GoalFormValues): UpdateGoalRequest {
  return toCreateGoal(v);
}

export function toGoalFormValues(g: GoalRecord): GoalFormValues {
  return {
    title: g.title,
    // Coerce the Postgres-string numerics back to numbers for the form.
    targetValue: Number(g.targetValue),
    currentValue: Number(g.currentValue),
    // Pre-metric rows have no value on the wire; `manual` is both the backend
    // default and the behaviour those rows already had.
    metric: g.metric ?? 'manual',
    unit: g.unit ?? '',
    period: g.period,
  };
}
