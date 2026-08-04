import { useCallback, useState } from 'react';
import { toast } from 'sonner';
import { useRole, type Role } from '@/shared/rbac';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { useGetPermissionsQuery, useUpdatePermissionMutation } from '../api/permissionsApi';
import type { PermissionKey } from '../constants/permissionMatrixKeys';

// Drives the live RBAC matrix page:
//   - reads GET /permissions (effective matrix, locked cells, and what THIS actor
//     is allowed to change),
//   - exposes whether the current user may edit,
//   - toggles a cell via PUT /permissions with optimistic update (handled in the
//     API's onQueryStarted) and surfaces the backend's 400/403 message verbatim.
//
// `canEdit` comes from the SERVER, not from a role check here. The editable
// audience is defined once, in the backend's PERMISSION_MATRIX_EDIT_ROLES.
// Re-deriving it client-side is how the UI ends up disagreeing with the API —
// which is exactly what happened before: this hook hardcoded "super admin only"
// and showed every Owner a permanently read-only grid.
export function usePermissionMatrix() {
  // The "viewing as" switcher previews a lesser persona, so it must not offer an
  // action that persona could not perform — even though the JWT (and therefore
  // the server's canEdit) still reflects the real role.
  const { isViewingAs } = useRole();

  const { data, isLoading, isFetching, isError, error, refetch } = useGetPermissionsQuery();
  const canEdit = (data?.canEdit ?? false) && !isViewingAs;
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
    isViewingAs,
    pendingCell,
    toggle,
  };
}
