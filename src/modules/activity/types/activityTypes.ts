import type { ActivityType } from '@/shared/constants/activityTypeConstants';
import type { ID, ISODateString, PaginationParams, ProspectNote, Reminder } from '@/shared/types';

export type { ProspectNote, Reminder };

export interface DailyGoal {
  id: string;
  label: string;
  current: number;
  target: number;
}

// GET /activity feed item — mirrors backend AuditLogResponseDto.
export interface ActivityFeedItem {
  id: ID;
  tenantId: ID | null;
  userId: ID | null;
  action: string;
  resource: string | null;
  resourceId: ID | null;
  meta: Record<string, unknown>;
  /** Resolved display name of the actor; "System" for system-written rows. */
  actorName: string;
  actorEmail: string | null;
  createdAt: ISODateString;
}

// --- Backend record shapes (under /api) -------------------------------------

// wemarketplus-backend/src/tasks/dto/task-response.dto.ts
export const TaskPriority = {
  Urgent: 'urgent',
  High: 'high',
  Medium: 'medium',
  Low: 'low',
} as const;
export type TaskPriority = (typeof TaskPriority)[keyof typeof TaskPriority];

export const TaskStatus = {
  Pending: 'pending',
  InProgress: 'in_progress',
  Completed: 'completed',
  Cancelled: 'cancelled',
} as const;
export type TaskStatus = (typeof TaskStatus)[keyof typeof TaskStatus];

export interface TaskRecord {
  id: ID;
  tenantId: ID;
  title: string;
  description: string | null;
  prospectId: ID | null;
  dueDate: string | null;
  priority: TaskPriority;
  status: TaskStatus;
  assignedTo: ID | null;
  completedAt: ISODateString | null;
  createdBy: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateTaskRequest {
  title: string;
  description?: string;
  prospectId?: string;
  dueDate?: string;
  priority?: TaskPriority;
  status?: TaskStatus;
  assignedTo?: string;
}

export type UpdateTaskRequest = Partial<CreateTaskRequest>;

export interface ListTasksQuery extends PaginationParams {
  status?: TaskStatus;
  assignedTo?: string;
  prospectId?: string;
}

// wemarketplus-backend/src/notes/dto/note-response.dto.ts
export interface NoteRecord {
  id: ID;
  tenantId: ID;
  /** Nullable since FIX-1: a note may target an account or a person instead. */
  prospectId: ID | null;
  referralSourceId: ID | null;
  contactId: ID | null;
  summary: string;
  activityType: ActivityType | null;
  activityTypeOther: string | null;
  /** @deprecated Superseded by `activityType`; retained for older rows. */
  contactType: string | null;
  urgency: 'hot' | 'warm' | 'cold';
  patientStatus: string | null;
  barriers: string | null;
  nextStep: string | null;
  nextStepLabel: string | null;
  followUpDate: string | null;
  followUpTime: string | null;
  assignedTo: ID | null;
  gpsLocation: string | null;
  /** Reminder auto-created from `followUpDate` (FIX-4). */
  followUpReminderId: ID | null;
  isHotLead: boolean;
  createdBy: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateNoteRequest {
  /**
   * All three targets are individually optional but AT LEAST ONE is required —
   * the backend 400s otherwise (NotesService.assertHasTarget), and
   * CHK_notes_has_target enforces it in the database too.
   */
  prospectId?: string;
  referralSourceId?: string;
  contactId?: string;
  summary: string;
  activityType?: ActivityType;
  /** Required when `activityType` is `other`. */
  activityTypeOther?: string;
  /** @deprecated Superseded by `activityType`. */
  contactType?: string;
  urgency?: 'hot' | 'warm' | 'cold';
  patientStatus?: string;
  barriers?: string;
  nextStep?: string;
  nextStepLabel?: string;
  followUpDate?: string;
  followUpTime?: string;
  assignedTo?: string;
  gpsLocation?: string;
  isHotLead?: boolean;
}

// Backend UpdateNoteDto excludes all three target ids — a note cannot be
// re-linked once written, which is what makes it a trustworthy activity record.
export type UpdateNoteRequest = Partial<
  Omit<CreateNoteRequest, 'prospectId' | 'referralSourceId' | 'contactId'>
>;

export interface ListNotesQuery extends PaginationParams {
  prospectId?: string;
  /** Notes on a facility/account — powers the Referral Source notes panel. */
  referralSourceId?: string;
  /** Notes on a person. */
  contactId?: string;
}

// wemarketplus-backend/src/goals/dto/goal-response.dto.ts
export type GoalPeriod = 'daily' | 'weekly' | 'monthly' | 'quarterly' | 'yearly';

export interface GoalRecord {
  id: ID;
  tenantId: ID;
  userId: ID | null;
  title: string;
  targetValue: number;
  currentValue: number;
  unit: string;
  period: GoalPeriod;
  startDate: string | null;
  endDate: string | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface CreateGoalRequest {
  title: string;
  targetValue: number;
  userId?: string;
  currentValue?: number;
  unit?: string;
  period?: GoalPeriod;
  startDate?: string;
  endDate?: string;
}

export type UpdateGoalRequest = Partial<CreateGoalRequest>;

export interface ActivityUiState {
  // Activity tab on the page (calendar, notes, reminders, goals).
  activeTab: 'calendar' | 'notes' | 'reminders' | 'goals';
}
