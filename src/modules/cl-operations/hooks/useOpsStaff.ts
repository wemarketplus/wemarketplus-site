import { useMemo } from 'react';
import { useListAssignableStaffQuery } from '@/modules/users';

/**
 * The tenant's assignable staff, for the operations boards: options for an
 * "Assigned to" picker, and an id -> name resolver for the column that reads it
 * back.
 *
 * `/users/assignable`, NOT `GET /users`. The full user list is
 * @Roles(Admin, Owner, Manager), and the people who work these boards —
 * Housekeeping and Maintenance — are none of those, so the shared `useUserLookup`
 * would 403 and leave the picker permanently empty for exactly the personas the
 * guide tells to assign work. `/users/assignable` is the id+name projection that
 * exists for this (see StaffOptionDto).
 *
 * Fetched unconditionally rather than gated on a modal being open, because the
 * TABLE needs the names on first paint — an "Assigned to" column showing a uuid
 * until you happen to open a form is worse than one extra request.
 */
export function useOpsStaff() {
  const { data, isLoading } = useListAssignableStaffQuery();

  const staffOptions = useMemo(
    () =>
      isLoading
        ? undefined
        : (data ?? []).map((s) => ({ value: s.id, label: s.name })),
    [data, isLoading],
  );

  // An unresolved id yields 'Unassigned', never the raw uuid: a uuid on screen
  // looks like data while telling the reader nothing (see useRecordLookups).
  const assigneeName = useMemo(() => {
    const byId = new Map((data ?? []).map((s) => [s.id, s.name]));
    return (id: string | null) => (id ? (byId.get(id) ?? 'Unassigned') : '—');
  }, [data]);

  return { staffOptions, assigneeName };
}
