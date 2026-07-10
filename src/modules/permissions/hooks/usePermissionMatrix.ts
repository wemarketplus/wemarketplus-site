import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { Role, useRole } from '@/shared/rbac';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useGetPermissionsQuery, useUpdatePermissionMutation } from '../api/permissionsApi';
import type { PermissionKey } from '../constants/permissionMatrixKeys';

// Drives the live RBAC matrix page:
//   - reads GET /permissions (effective matrix + locked cells),
//   - exposes whether the current user may edit (super admin only — the backend
//     @Roles(SuperAdmin) gate returns 403 for anyone else),
//   - toggles a cell via PUT /permissions with optimistic update (handled in the
//     API's onQueryStarted) and surfaces the backend's 400/403 message verbatim.
export function usePermissionMatrix() {
  const { is } = useRole();
  const canEdit = is(Role.SuperAdmin);

  const { data, isLoading, isFetching, isError, error, refetch } = useGetPermissionsQuery();
  const [updatePermission] = useUpdatePermissionMutation();

  // Tracks the cell currently being saved so the grid can disable just that
  // checkbox (`${permission}:${role}`).
  const [pendingCell, setPendingCell] = useState<string | null>(null);

  const toggle = useCallback(
    async (permission: PermissionKey, role: Role, value: boolean) => {
      if (!canEdit) return;
      const cellId = `${permission}:${role}`;
      setPendingCell(cellId);
      try {
        await updatePermission({ permission, role, value }).unwrap();
        toast.success('Permission updated');
      } catch (err) {
        // Surface the backend message verbatim: locked/unknown key -> 400,
        // not a super admin -> 403. The optimistic patch is already rolled back
        // in the mutation's onQueryStarted.
        toast.error(extractApiErrorMessage(err, 'Could not update permission'));
      } finally {
        setPendingCell(null);
      }
    },
    [canEdit, updatePermission],
  );

  return {
    view: data,
    isLoading,
    isFetching,
    isError,
    errorMessage: isError ? extractApiErrorMessage(error, 'Could not load permissions') : null,
    refetch,
    canEdit,
    pendingCell,
    toggle,
  };
}
