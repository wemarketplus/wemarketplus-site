import type { ISODateString } from '@/shared/types';
import type { AppointmentRecord } from '@/modules/appointments/types/appointmentsTypes';
import type { JobRecord } from '@/modules/jobs/types/jobsTypes';
import type { TaskRecord } from '@/modules/activity/types/activityTypes';
import type { ProspectRecord } from '@/modules/prospects/types/prospectsTypes';
import type { ReferralSourceRecord } from '@/modules/referrals/types/referralsTypes';
import type { ClLeadRecord } from '@/modules/cl-leads/types/clLeadApiTypes';
import type { ClTourRecord } from '@/modules/cl-tours/types/clToursApiTypes';
import type {
  ClHousekeepingTaskRecord,
  ClMaintenanceTicketRecord,
  ClMakeReadyTaskRecord,
} from '@/modules/cl-operations/types/clOperationsApiTypes';

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

/**
 * GET /cl/daily-queue — the CommunityLink counterpart.
 *
 * Its own shape rather than a widened `DailyQueue`, because the two products
 * share not one section: HospiceLink's queue is tasks/jobs/appointments/cold
 * accounts/re-engagement over `prospects` and `referral_sources`; this one is
 * lead follow-ups, today's tours and quiet leads over `cl_leads` and `cl_tours`.
 * A union type with ten optional arrays would let a page render a section the
 * active product can never fill.
 *
 * The three sections are the three the end-user guide names — see
 * ClDailyQueueService for why CommunityLink tasks are deliberately not among
 * them.
 */
export interface ClDailyQueue {
  /** `YYYY-MM-DD` the queue was built for. */
  date: string;
  /** Leads whose follow-up date has arrived or passed, most overdue first. */
  followUpsDue: ClLeadRecord[];
  /** Tours still `scheduled` for today, earliest first. */
  toursToday: ClTourRecord[];
  /** Active leads untouched past the quiet threshold, quietest first. */
  quietLeads: ClLeadRecord[];
  /** Server-computed so a badge cannot disagree with the list it counts. */
  totalItems: number;
}

/**
 * GET /cl/field-queue — "My Queue" for a CommunityLink field technician.
 *
 * A THIRD shape rather than a widened ClDailyQueue, for the same reason that one is
 * separate from DailyQueue: it shares no section with either. This queue is work
 * orders over `cl_maintenance_tickets`, `cl_make_ready_tasks` and
 * `cl_housekeeping_tasks`, and unlike the sales queue every row is scoped to the
 * caller — those three tables have an `assignedTo` column, `cl_leads` does not.
 *
 * A SECTION IS EMPTY WHEN THE ROLE DOES NOT WORK IT, not merely when there is
 * nothing to do: the server omits tickets for Housekeeping and housekeeping tasks
 * for Maintenance. The page keys its rendering off the role for that reason — see
 * ClFieldQueuePage — so an empty array never reads as "you are all caught up" on a
 * board the reader cannot open.
 */
export interface ClFieldQueue {
  /** `YYYY-MM-DD` the queue was built for. */
  date: string;
  /** Open tickets assigned to the caller, most urgent first. */
  maintenanceTickets: ClMaintenanceTicketRecord[];
  /** Unfinished make-ready tasks assigned to the caller and due, oldest first. */
  makeReadyTasks: ClMakeReadyTaskRecord[];
  /** Unfinished housekeeping tasks assigned to the caller and due, oldest first. */
  housekeepingTasks: ClHousekeepingTaskRecord[];
  /** Server-computed so a badge cannot disagree with the list it counts. */
  totalItems: number;
}
