import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { useListAssignableStaffQuery } from '../api/usersApi';

export interface TenantStaffOptions {
  /** Assignable people, as `<option>` data. Never empty for a signed-in user. */
  options: readonly EntitySelectOption[];
  /**
   * Whether `options` is the tenant's real directory rather than just the signed-in
   * user. Kept in the API because callers render a different caption for the
   * degraded case ("you can assign yourself") and that copy must not appear when
   * the picker is genuinely complete.
   *
   * Now false only when the directory request has not produced anyone yet — no
   * longer a per-ROLE answer. See the note on the hook.
   */
  isFullDirectory: boolean;
  isLoading: boolean;
}

/**
 * The tenant's assignable people, for any "who is doing this?" picker.
 *
 * READS `GET /users/assignable`, NOT `GET /users`. This used to call the paginated
 * user list, which is `@Roles(Admin, Owner, Manager)` server-side — so the query
 * was skipped for exactly the roles that most need to assign work (Marketer,
 * Sales/Admissions) and they were handed a one-entry picker containing themselves.
 * On HospiceLink that was the whole reason a patient or visit could not be given to
 * a Nurse or Caregiver from the UI: `assignedRep` defaults to the caller
 * (`AppointmentsService` does `dto.assignedRep ?? actorId`), so a marketer could
 * only ever book onto their own calendar, the clinical user's `my-patients` stayed
 * empty, and Family Communication and Notes had no patient to attach to.
 *
 * `/users/assignable` exists for this and carries NO `@Roles()` — it returns id and
 * name only (`StaffOptionDto`), leaving every sensitive column unselected at the
 * repository, which is what makes it safe to open to a field persona. So there is
 * no longer a role that gets a degraded picker.
 *
 * Deactivated users are excluded server-side (the repository selects active only),
 * so there is no `isActive` filter here — adding one would silently depend on a
 * field this projection deliberately does not return.
 */
export function useTenantStaffOptions(enabled = true): TenantStaffOptions {
  const me = useAppSelector((s) => s.auth.user);

  const { data, isLoading } = useListAssignableStaffQuery(undefined, {
    skip: !enabled,
  });

  return useMemo(() => {
    const options = (data ?? []).map((staff) => ({
      value: staff.id,
      label: staff.name,
    }));

    if (options.length > 0) {
      return { options, isFullDirectory: true, isLoading };
    }

    // Nothing back yet, or a tenant of one. Offering the signed-in user keeps the
    // form submittable rather than presenting an empty dropdown.
    return {
      options: me ? [{ value: me.id, label: 'Me' }] : [],
      isFullDirectory: false,
      isLoading,
    };
  }, [data, isLoading, me]);
}
