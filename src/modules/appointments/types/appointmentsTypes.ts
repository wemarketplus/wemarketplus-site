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
  nextJobType?: JobType;
  nextJobObjective?: string;
  nextJobDueDate?: string;
  nextJobAssignedTo?: string;
}

export interface AppointmentsUiState {
  statusFilter: AppointmentStatus | 'all';
}
