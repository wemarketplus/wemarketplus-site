import type { Role } from '@/shared/rbac';
import type { PermissionKey } from '../constants/permissionMatrixKeys';

// Backend permission-matrix shapes — wemarketplus-backend/src/permissions
// (PermissionsView). Distinct from the UI role-capability types in permissionsTypes.
export type PermissionMatrix = Record<string, Partial<Record<Role, boolean>>>;

export interface PermissionsView {
  permissions: PermissionMatrix;
  locked: PermissionMatrix;
}

export interface UpdatePermissionRequest {
  permission: PermissionKey;
  role: Role;
  value: boolean;
}
