// `shared/rbac` is the app-wide *enforcement mechanism*: the gate component,
// the hook that reads the current user's role, and the role constants. It is
// intentionally distinct from `modules/permissions`, which is reserved for a
// future admin CRUD over permission records. Do not blur this boundary.

export { PermissionGate, RoleGate } from './components/PermissionGate';
export { usePermission, useRole } from './hooks/usePermission';
export { Role, ALL_ROLES } from './types/permissionTypes';
export {
  ROLE_LABELS,
  STAFF_ROLES,
  ADMIN_ONLY,
  SUPER_ADMIN_ONLY,
  CL_MANAGEMENT_ROLES,
  CL_SALES_ROLES,
  CL_FINANCIAL_ROLES,
  CL_INVENTORY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_MAKE_READY_ROLES,
} from './constants/permissionsConstants';
