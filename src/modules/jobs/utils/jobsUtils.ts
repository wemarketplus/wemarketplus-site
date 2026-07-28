import type { JobRecord } from '../types/jobsTypes';
import { JobStatus } from '../types/jobsTypes';

/** YYYY-MM-DD for the LOCAL calendar day (never via toISOString/UTC). */
function toLocalDateOnly(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/** Overdue = has a due date in the past and is not finished. */
export function isOverdue(job: JobRecord, today = new Date()): boolean {
  if (!job.dueDate) return false;
  if (job.status === JobStatus.Completed || job.status === JobStatus.Cancelled) {
    return false;
  }
  // dueDate is a date-only string produced from the LOCAL calendar day by the
  // backend, so compare against the local day too — toISOString() would read the
  // UTC day and flag jobs as overdue a day early for timezones ahead of UTC.
  return job.dueDate < toLocalDateOnly(today);
}

/** Jobs the backend spawned from a stage transition, rather than a person. */
export function isAutomated(job: JobRecord): boolean {
  return job.triggerStage !== null;
}
