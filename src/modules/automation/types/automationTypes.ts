import type { ID, ISODateString } from '@/shared/types';
import type { TaskStatus } from '@/modules/activity/types/activityTypes';

/**
 * One standing follow-up on a prospect. Mirrors the backend
 * FollowUpAutomationDto (wemarketplus-backend/src/automation/dto/
 * follow-up-response.dto.ts).
 *
 * `id` is a `tasks` row id, and that is the feature rather than an
 * implementation leak: an automation created here IS a reminder, so it shows up
 * in the Daily tasks queue and can be completed from there. There is no separate
 * automations table for the client to reconcile against.
 *
 * `prospectId` and `dueDate` are NON-NULL here while TaskRecord has both
 * nullable — the backend only calls a task an automation when it has both, so
 * the table can render a prospect and a date on every row without guards.
 */
export interface FollowUpAutomationRecord {
  id: ID;
  tenantId: ID;
  prospectId: ID;
  title: string;
  /** `YYYY-MM-DD`. Compared as a string, never parsed to an instant. */
  dueDate: string;
  /** Free text ("fortnightly until the face-to-face"), not a recurrence rule. */
  cadenceNote: string | null;
  status: TaskStatus;
  assignedTo: ID | null;
  createdAt: ISODateString;
}

/**
 * POST /automation/follow-ups. Deliberately narrower than CreateTaskRequest:
 * prospectId and dueDate are required (a dateless reminder can never surface in
 * the daily queue), and there is no `assignedTo` — the backend assigns to the
 * caller so the reminder lands in their own day.
 */
export interface CreateFollowUpRequest {
  prospectId: string;
  title: string;
  dueDate: string;
  cadenceNote?: string;
}

/** GET /automation/follow-ups. No page/limit — the backend returns a bounded list. */
export interface ListFollowUpsQuery {
  prospectId?: string;
}
