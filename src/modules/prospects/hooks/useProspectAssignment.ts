import { toast } from 'sonner';
import { useListAppointmentsQuery, useUpdateAppointmentMutation } from '@/modules/appointments';
import type { AppointmentRecord } from '@/modules/appointments/types/appointmentsTypes';
import { useListJobsQuery } from '@/modules/jobs';
import { JobStatus } from '@/modules/jobs/types/jobsTypes';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';

export interface ProspectAssignmentController {
  /**
   * The visit an "assign nurse/caregiver" control would apply to. Undefined
   * when the prospect has no visit yet — nothing has been scheduled, so there
   * is no `assignedRep` for a control to write.
   */
  appointment: AppointmentRecord | undefined;
  isLoading: boolean;
  /** PATCHes `assignedRep` on that visit. Resolves true when it landed. */
  assign: (userId: string) => Promise<boolean>;
  isSaving: boolean;
}

/** Jobs still open enough that reassigning their visit is live work, not history. */
const OPEN_JOB_STATUSES: ReadonlySet<JobStatus> = new Set([
  JobStatus.Open,
  JobStatus.Scheduled,
  JobStatus.InProgress,
]);

/**
 * The clinical assignment for a prospect's DRAWER — `appointments.assignedRep`,
 * NOT `prospects.assignedTo` (the pipeline owner; see useProspectOwner for that
 * split, including why the two are easy to confuse).
 *
 * `appointments` carries no `pipelineId` of its own: the chain is
 * appointment.jobId -> job.pipelineId -> prospect.id, same as the backend's own
 * `myPatients`/`withPatientNames` (AppointmentsService). This resolves it the
 * same way — the prospect's jobs first, then the appointment on whichever job is
 * still open, falling back to the most recently created job when every one of
 * them is done or cancelled, so a closed-out patient still shows who last had
 * them rather than looking unassigned.
 *
 * A prospect can in principle have more than one open job (more than one visit
 * in flight), each with its own assignee. This surfaces exactly one — the
 * drawer's "who has this patient right now" control, not a full visit list —
 * which matches its one `assignedTo` picker for the pipeline owner just above
 * it in the same drawer.
 */
export function useProspectAssignment(
  prospectId: string | null,
): ProspectAssignmentController {
  const { data: jobs, isFetching: isJobsFetching } = useListJobsQuery(
    { pipelineId: prospectId ?? undefined },
    { skip: !prospectId },
  );

  const job =
    jobs?.data.find((j) => OPEN_JOB_STATUSES.has(j.status)) ?? jobs?.data[0];

  const { data: appointments, isFetching: isAppointmentsFetching } =
    useListAppointmentsQuery({ jobId: job?.id }, { skip: !job });

  const [updateAppointment, { isLoading: isSaving }] =
    useUpdateAppointmentMutation();

  // Appointments come back most-recent-first (the backend's default order) —
  // the visit worth assigning.
  const appointment = appointments?.data[0];

  const assign = async (userId: string): Promise<boolean> => {
    if (!appointment) return false;
    try {
      await updateAppointment({
        id: appointment.id,
        patch: { assignedRep: userId },
      }).unwrap();
      toast.success('Assignment updated.');
      return true;
    } catch (error) {
      toast.error(
        extractApiErrorMessage(error, 'Could not change the assignment.'),
      );
      return false;
    }
  };

  return {
    appointment,
    isLoading: isJobsFetching || (Boolean(job) && isAppointmentsFetching),
    assign,
    isSaving,
  };
}
