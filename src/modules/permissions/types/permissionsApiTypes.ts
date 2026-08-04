import type { Role } from '@/shared/rbac';
import type { PermissionKey } from '../constants/permissionMatrixKeys';

// Backend permission-matrix shapes — wemarketplus-backend/src/permissions
// (ActorPermissionsView). Distinct from the UI role-capability types in
// permissionsTypes.
export type PermissionMatrix = Record<string, Partial<Record<Role, boolean>>>;

export interface PermissionsView {
  permissions: PermissionMatrix;
  /** Cells locked by product policy — nobody can change these. */
  locked: PermissionMatrix;
  /**
   * Whether the signed-in user may edit the matrix at all. SERVER-AUTHORITATIVE:
   * the API decides it, so the UI never keeps its own copy of the rule and drift
   * from what PUT /permissions will actually accept is impossible.
   */
  canEdit: boolean;
  /**
   * Cells this user specifically may not change, though a super admin could — the
   * super_admin column, and every cell of `assign_super_admin`. Kept separate from
   * `locked` so the UI can say which of the two applies.
   */
  restricted: PermissionMatrix;
}

export interface UpdatePermissionRequest {
  permission: PermissionKey;
  role: Role;
  value: boolean;
}
