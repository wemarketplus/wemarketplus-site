// `shared/rbac` is the app-wide *enforcement mechanism*: the gate component,
// the hook that reads the current user's role, and the role constants. It is
// intentionally distinct from `modules/permissions`, which is reserved for a
// future admin CRUD over permission records. Do not blur this boundary.

export { PermissionGate, RoleGate } from './components/PermissionGate';
export { usePermission, useRole } from './hooks/usePermission';
export { Role, ALL_ROLES, type CustomRole } from './types/permissionTypes';
export {
  roleTitle,
  ROLE_LABELS,
  STAFF_ROLES,
  ADMIN_ONLY,
  SUPER_ADMIN_ONLY,
  HL_MANAGEMENT_ROLES,
  HL_MARKETING_ROLES,
  HL_CLINICAL_ROLES,
  HL_FIELD_ROLES,
  CL_MANAGEMENT_ROLES,
  CL_SALES_ROLES,
  CL_FINANCIAL_ROLES,
  CL_INVENTORY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_MAKE_READY_ROLES,
  CL_ALL_ROLES,
  CL_UNIT_STATUS_ROLES,
  CL_FIELD_ROLES,
  CL_MAINTENANCE_VIEW_ROLES,
  CL_COMPETITOR_INTEL_ROLES,
  CL_FIELD_ACTIVITY_ROLES,
  CL_CARE_ROLES,
  CL_ACTIVITY_NOTES_ROLES,
  CL_RESIDENT_CARE_ROLES,
  CL_MILEAGE_ROLES,
  CALENDAR_ROLES,
} from './constants/permissionsConstants';
