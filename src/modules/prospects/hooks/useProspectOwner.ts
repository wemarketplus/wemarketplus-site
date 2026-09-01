import { toast } from 'sonner';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useUpdateProspectMutation } from '../api/prospectsApi';

export interface ProspectOwnerController {
  /** Reassigns the pipeline row's owner. Resolves true when the PATCH landed. */
  assign: (prospectId: string, userId: string) => Promise<boolean>;
  isSaving: boolean;
}

/**
 * Reassigning a prospect's OWNER, inline from the pipeline table.
 *
 * ── What was actually missing ─────────────────────────────────────────────────
 * `prospects.assignedTo` has always been a real, role-gated column with a real
 * endpoint behind it — `PATCH /prospects/:id` accepts it, and the create path
 * defaults it to the caller. What it never had was a control: the Prospects table
 * printed the owner's name in a read-only "Marketer" column, no form offered the
 * field, and nothing in the frontend sent it. So changing a prospect's owner was
 * possible only by calling the API directly, which is what "API-only" meant for
 * this field.
 *
 * ── What this is NOT ──────────────────────────────────────────────────────────
 * This is not the clinical assignment. There are two unrelated "assignment"
 * concepts on a HospiceLink patient and conflating them is the easiest mistake to
 * make here:
 *
 *   - `prospects.assignedTo` — the pipeline OWNER, a marketer. This hook.
 *   - `appointments.assignedRep` — the clinician a VISIT belongs to. That is what
 *     fills a nurse's "My patients" and their own visit schedule, and it has a
 *     control in three places now: the "Assign to" picker in the two scheduling
 *     modals (for a visit being booked) and the Prospect drawer's own "Clinical
 *     assignment" picker (for reassigning one already on the calendar — see
 *     useProspectAssignment).
 *
 * Giving a patient to a nurse means assigning them a visit, not changing this
 * field. Both are needed; only one of them was missing a UI.
 *
 * ── Authorization ─────────────────────────────────────────────────────────────
 * Nothing is enforced here, deliberately. `ProspectsController` is gated to the
 * marketing/management roles, so a Nurse or Caregiver is refused server-side and
 * never sees this screen in the first place. The picker's options come from
 * `GET /users/assignable`, which returns id and name only — safe to read from any
 * role, and the reason a Marketer can populate this list at all.
 */
export function useProspectOwner(): ProspectOwnerController {
  const [updateProspect, { isLoading }] = useUpdateProspectMutation();

  const assign = async (prospectId: string, userId: string) => {
    try {
      await updateProspect({
        id: prospectId,
        patch: { assignedTo: userId },
      }).unwrap();
      toast.success('Owner updated.');
      return true;
    } catch (error) {
      // Surfaces the API's own message where there is one — a 403 here means the
      // caller's role cannot own pipeline rows, which is worth reading verbatim
      // rather than flattening into "something went wrong".
      toast.error(extractApiErrorMessage(error, 'Could not change the owner.'));
      return false;
    }
  };

  return { assign, isSaving: isLoading };
}
