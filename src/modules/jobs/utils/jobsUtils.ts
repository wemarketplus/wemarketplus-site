import type { JobRecord } from '../types/jobsTypes';
import { JobStatus } from '../types/jobsTypes';

/** Overdue = has a due date in the past and is not finished. */
export function isOverdue(job: JobRecord, today = new Date()): boolean {
  if (!job.dueDate) return false;
  if (job.status === JobStatus.Completed || job.status === JobStatus.Cancelled) {
    return false;
  }
  // dueDate is a date-only string; compare on the date boundary, not the instant.
  return job.dueDate < today.toISOString().slice(0, 10);
}

/** Jobs the backend spawned from a stage transition, rather than a person. */
export function isAutomated(job: JobRecord): boolean {
  return job.triggerStage !== null;
}
