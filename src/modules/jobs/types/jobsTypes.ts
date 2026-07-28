import type { ID, ISODateString, PaginationParams } from '@/shared/types';
import type { ProspectStage } from '@/modules/prospects/types/prospectsTypes';

// Backend enums — wemarketplus-backend/src/jobs/jobs.constants.ts.
export const JobType = {
  AssessmentVisit: 'assessment_visit',
  InService: 'in_service',
  FollowUp: 'follow_up',
  DropIn: 'drop_in',
  Presentation: 'presentation',
  Paperwork: 'paperwork',
} as const;
export type JobType = (typeof JobType)[keyof typeof JobType];

export const JobPriority = {
  Low: 'low',
  Normal: 'normal',
  High: 'high',
} as const;
export type JobPriority = (typeof JobPriority)[keyof typeof JobPriority];

export const JobStatus = {
  Open: 'open',
  Scheduled: 'scheduled',
  InProgress: 'in_progress',
  Completed: 'completed',
  Cancelled: 'cancelled',
} as const;
export type JobStatus = (typeof JobStatus)[keyof typeof JobStatus];

// Mirrors wemarketplus-backend/src/jobs/dto/job-response.dto.ts.
export interface JobRecord {
  id: ID;
  tenantId: ID;
  jobType: JobType;
  pipelineId: ID;
  companyId: ID | null;
  contactId: ID | null;
  /** The pipeline stage whose transition spawned this job; null if hand-created. */
  triggerStage: ProspectStage | null;
  assignedTo: ID | null;
  priority: JobPriority;
  dueDate: string | null;
  objective: string | null;
  status: JobStatus;
  outcome: string | null;
  completedAt: ISODateString | null;
  createdBy: ID | null;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

// POST /hl/jobs body.
export interface CreateJobRequest {
  jobType: JobType;
  pipelineId: string;
  companyId?: string;
  contactId?: string;
  assignedTo?: string;
  priority?: JobPriority;
  dueDate?: string;
  objective?: string;
  status?: JobStatus;
  outcome?: string;
}

// PATCH /hl/jobs/:id — pipelineId is NOT updatable server-side (it would orphan
// the job's appointments), so it is omitted here too.
export type UpdateJobRequest = Partial<Omit<CreateJobRequest, 'pipelineId'>>;

// GET /hl/jobs query.
export interface ListJobsQuery extends PaginationParams {
  pipelineId?: string;
  companyId?: string;
  contactId?: string;
  assignedTo?: string;
  jobType?: JobType;
  status?: JobStatus;
  priority?: JobPriority;
}

export interface JobsUiState {
  statusFilter: JobStatus | 'all';
  typeFilter: JobType | 'all';
}
