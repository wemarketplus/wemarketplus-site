import type { ActivityType } from '@/shared/constants/activityTypeConstants';
import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { JobType } from '@/modules/jobs/types/jobsTypes';

// Backend enums — wemarketplus-backend/src/appointments/appointments.constants.ts.
export const AppointmentType = {
  InPerson: 'in_person',
  Call: 'call',
  Virtual: 'virtual',
} as const;
export type AppointmentType =
  (typeof AppointmentType)[keyof typeof AppointmentType];

export const AppointmentStatus = {
  Scheduled: 'scheduled',
  Completed: 'completed',
  NoShow: 'no_show',
  Cancelled: 'cancelled',
  Rescheduled: 'rescheduled',
} as const;
export type AppointmentStatus =
  (typeof AppointmentStatus)[keyof typeof AppointmentStatus];

export const AppointmentOutcome = {
  Positive: 'positive',
  Neutral: 'neutral',
  FollowUpNeeded: 'follow_up_needed',
} as const;
export type AppointmentOutcome =
  (typeof AppointmentOutcome)[keyof typeof AppointmentOutcome];

// Mirrors wemarketplus-backend/src/appointments/dto/appointment-response.dto.ts.
export interface AppointmentRecord {
  id: ID;
  tenantId: ID;
  jobId: ID;
  title: string;
  startAt: ISODateString;
  endAt: ISODateString;
  appointmentType: AppointmentType;
  location: string | null;
  /** Always an array — the backend normalises null away. */
  attendeeIds: ID[];
  assignedRep: ID | null;
  status: AppointmentStatus;
  visitNotes: string | null;
  outcome: AppointmentOutcome | null;
  /** The follow-up job this visit chained to on completion. */
  nextJobId: ID | null;
  completedAt: ISODateString | null;
  createdBy: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
  /**
   * Who the visit is for, resolved server-side through job → pipeline → prospect.
   * Null for an appointment with no patient behind it (an in-service, say).
   */
  patientName: string | null;
}

// POST /hl/appointments body.
export interface CreateAppointmentRequest {
  jobId: string;
  title: string;
  startAt: string;
  endAt: string;
  appointmentType?: AppointmentType;
  location?: string;
  attendeeIds?: string[];
  assignedRep?: string;
  status?: AppointmentStatus;
  visitNotes?: string;
  outcome?: AppointmentOutcome;
}

// PATCH /hl/appointments/:id — jobId is not updatable server-side.
export type UpdateAppointmentRequest = Partial<
  Omit<CreateAppointmentRequest, 'jobId'>
>;

// GET /hl/appointments query.
export interface ListAppointmentsQuery extends PaginationParams {
  jobId?: string;
  assignedRep?: string;
  status?: AppointmentStatus;
  appointmentType?: AppointmentType;
  outcome?: AppointmentOutcome;
}

// GET /hl/appointments/calendar query — both bounds required, window is capped
// server-side at 180 days / 500 rows.
export interface CalendarQuery {
  from: string;
  to: string;
  assignedRep?: string;
}

// POST /hl/appointments/:id/complete body. Supplying any nextJob* field forces
// chaining regardless of outcome.
export interface CompleteAppointmentRequest {
  outcome: AppointmentOutcome;
  visitNotes?: string;
  /**
   * WHAT happened (FIX-3) — the canonical enum shared with notes. Distinct from
   * `appointmentType`, which is the channel: a brochure drop-off and a
   * lunch-and-learn are both `in_person`.
   */
  activityType?: ActivityType;
  /** Required when `activityType` is `other`, or the backend 400s. */
  activityTypeOther?: string;
  /**
   * What was PROMISED at this visit (FIX-4). Setting `nextStepsDueDate` makes the
   * backend auto-create a Reminder for the visit's rep — deliberately separate
   * from `nextJob*`, which chains the next piece of field work.
   */
  nextSteps?: string;
  nextStepsDueDate?: string;
  nextJobType?: JobType;
  nextJobObjective?: string;
  nextJobDueDate?: string;
  nextJobAssignedTo?: string;
}

export interface AppointmentsUiState {
  statusFilter: AppointmentStatus | 'all';
}

/**
 * POST /hl/appointments/schedule-visit.
 *
 * Exactly one of `pipelineId` (a patient referral) or `companyId` (a facility)
 * says what the visit is about. The backend creates the Job the appointment
 * needs — and, for a facility, resolves that account's outreach pipeline — so
 * the caller never has to know either exists.
 */
export interface ScheduleVisitRequest {
  pipelineId?: string;
  companyId?: string;
  contactId?: string;
  title: string;
  startAt: ISODateString;
  endAt: ISODateString;
  appointmentType?: AppointmentType;
  activityType?: ActivityType;
  location?: string;
  assignedRep?: string;
  objective?: string;
}

/**
 * One row of GET /hl/appointments/my-patients — a patient this user has visits
 * with, as a clinical role is allowed to see them.
 *
 * Mirrors wemarketplus-backend MyPatientResponseDto, and its narrowness is the
 * point: no DOB, diagnosis, address or emergency contact. Widening the audience of
 * the patient list must not widen the field list, so do NOT "upgrade" this to
 * ProspectRecord.
 */
export interface MyPatientRecord {
  id: ID;
  patientName: string;
  stage: string;
}
