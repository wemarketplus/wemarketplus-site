import type { ISODateString } from '@/shared/types';
import type { AppointmentRecord } from '@/modules/appointments/types/appointmentsTypes';
import type { JobRecord } from '@/modules/jobs/types/jobsTypes';
import type { TaskRecord } from '@/modules/activity/types/activityTypes';
import type { ProspectRecord } from '@/modules/prospects/types/prospectsTypes';
import type { ReferralSourceRecord } from '@/modules/referrals/types/referralsTypes';

/**
 * One row of the re-engagement queue — the prospect plus WHY it is listed.
 * Mirrors the backend's ReengagementRowDto.
 */
export interface ReengagementRow {
  prospect: ProspectRecord;
  lastActivityAt: ISODateString;
  daysInactive: number;
}

/**
 * GET /daily-queue — the marketer's whole day in one payload.
 *
 * Each section reuses the OWNING module's record type rather than a flattened
 * "queue item" union, exactly as the backend DTO does. The queue is a different
 * selection of existing records, not a new kind of record, so the client can
 * render each section with the component that already knows that shape.
 */
export interface DailyQueue {
  /** `YYYY-MM-DD` the queue was built for. */
  date: string;
  /** Reminders due today or already overdue, most overdue first. */
  tasksDue: TaskRecord[];
  /** Stage-spawned field work due today or overdue. */
  jobsDue: JobRecord[];
  appointmentsToday: AppointmentRecord[];
  /** Accounts past the 14-day cold threshold, most neglected first. */
  coldReferralSources: ReferralSourceRecord[];
  /** Open pipeline rows quiet past the 30-day threshold. */
  reengagementProspects: ReengagementRow[];
  /** Server-computed so a badge cannot disagree with the list it counts. */
  totalItems: number;
}
