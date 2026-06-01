// `shared/rbac` is the app-wide *enforcement mechanism*: the gate component,
// the hook that reads the current user's role, and the role constants. It is
// intentionally distinct from `modules/permissions`, which is reserved for a
// future admin CRUD over permission records. Do not blur this boundary.

export { PermissionGate, RoleGate } from './components/PermissionGate';
export { usePermission, useRole } from './hooks/usePermission';
export { Role, ALL_ROLES } from './types/permissionTypes';
export { ROLE_LABELS, STAFF_ROLES, ADMIN_ONLY } from './constants/permissionsConstants';
