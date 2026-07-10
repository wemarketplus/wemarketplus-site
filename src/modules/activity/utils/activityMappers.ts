import type { DailyGoal, GoalRecord, NoteRecord, TaskRecord } from '../types/activityTypes';
import type { ProspectNote, Reminder, Urgency } from '@/shared/types';

// Pure mappers from backend records onto the activity-page view-models.
// Kept in utils/ so the hooks stay orchestration-only.

export function toDailyGoal(g: GoalRecord): DailyGoal {
  return {
    id: g.id,
    label: g.title,
    current: g.currentValue,
    target: g.targetValue,
  };
}

// The backend NoteResponseDto doesn't store author/position/interactionType, so
// those render blank until the read model exposes them (createdBy is a user id).
export function toProspectNote(n: NoteRecord): ProspectNote {
  return {
    id: n.id,
    prospectId: n.prospectId,
    author: n.createdBy ?? '',
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
