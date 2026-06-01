import { Role } from '../types/permissionTypes';

// Human-readable labels for roles. Used in admin UIs (user list, role pickers).
export const ROLE_LABELS: Record<Role, string> = {
  [Role.Admin]: 'Administrator',
  [Role.Manager]: 'Manager',
  [Role.Rep]: 'Sales Rep',
};

// Convenience role groups for common gating decisions. Prefer naming a group
// here over inlining `['admin', 'manager']` at call sites — keeps intent
// readable and lets us re-tune the policy in one place.
export const STAFF_ROLES: readonly Role[] = [Role.Admin, Role.Manager];
export const ADMIN_ONLY: readonly Role[] = [Role.Admin];
