import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { STAFF_ROLES, useRole } from '@/shared/rbac';
import type { EntitySelectOption } from '@/shared/ui/entity';
import { useListUsersQuery } from '../api/usersApi';

export interface TenantStaffOptions {
  /** Assignable people, as `<option>` data. Never empty for a signed-in user. */
  options: readonly EntitySelectOption[];
  /**
   * False when the caller's role may not read the directory, so `options` holds
   * only the signed-in user. A form should say "Assign to me" rather than
   * "Assign to…" in that case — offering a picker with one entry looks broken.
   */
  isFullDirectory: boolean;
  isLoading: boolean;
}

/** How many users a staff picker loads. Tenants are single communities here. */
const STAFF_PAGE_SIZE = 100;

/**
 * The tenant's assignable people, for any "who is doing this?" picker.
 *
 * Lives in the users module because that module owns `/users`, and exists at all
 * because of an ASYMMETRY worth stating: `GET /users` is staff-only server-side,
 * but the people who most need to assign work — Marketer, Sales/Admissions — are
 * not in STAFF_ROLES. A picker that just called the endpoint would 403 for
 * exactly its main audience and render an empty dropdown.
 *
 * So the query is SKIPPED for those roles rather than allowed to fail, and they
 * get the one assignment they can always make truthfully: themselves. That is a
 * real limitation, not a stopgap dressed up — a marketer genuinely cannot book a
 * colleague's tour from here today. Widening it means either opening a
 * names-only directory endpoint (the way `/users/calendar-colors` is open to
 * every role because the shared calendar needs it) or admitting the sales roles
 * to `GET /users`; both are backend decisions.
 */
export function useTenantStaffOptions(enabled = true): TenantStaffOptions {
  const { isAny } = useRole();
  const me = useAppSelector((s) => s.auth.user);
  const canReadDirectory = isAny(STAFF_ROLES);

  const { data, isLoading } = useListUsersQuery(
    { page: 1, limit: STAFF_PAGE_SIZE },
    { skip: !enabled || !canReadDirectory },
  );

  return useMemo(() => {
    if (!canReadDirectory) {
      return {
        options: me ? [{ value: me.id, label: 'Me' }] : [],
        isFullDirectory: false,
        isLoading: false,
      };
    }

    const options = (data?.data ?? [])
      // Deactivated accounts stay in the list for history but must not be
      // assignable — new work should never land on someone who cannot sign in.
      .filter((user) => user.isActive)
      .map((user) => ({
        value: user.id,
        label:
          [user.firstName, user.lastName].filter(Boolean).join(' ').trim() ||
          user.email,
      }));

    return { options, isFullDirectory: true, isLoading };
  }, [canReadDirectory, data, isLoading, me]);
}
