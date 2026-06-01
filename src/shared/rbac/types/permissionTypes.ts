// The wemarketplus-backend is role-based, not permission-based. Roles come from
// `wemarketplus-backend/src/common/constants/roles.enum.ts` and are mirrored
// here verbatim — keep these in sync if a role is added on the backend.

export const Role = {
  Admin: 'admin',
  Manager: 'manager',
  Rep: 'rep',
} as const;

export type Role = (typeof Role)[keyof typeof Role];

export const ALL_ROLES: readonly Role[] = [Role.Admin, Role.Manager, Role.Rep];
