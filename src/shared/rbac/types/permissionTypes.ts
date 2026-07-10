// The wemarketplus-backend is role-based, not permission-based. Roles come from
// `wemarketplus-backend/src/common/constants/roles.enum.ts` and are mirrored
// here verbatim — keep these in sync if a role is added on the backend.

export const Role = {
  // Platform super administrator — highest privilege tier.
  SuperAdmin: 'super_admin',
  // Tenant administrator — full access within the tenant.
  Admin: 'admin',
  // Tenant owner — business owner / billing authority (default for self-register).
  Owner: 'owner',
  // Team manager — elevated read across the tenant.
  Manager: 'manager',
  // Field marketer — primary HospiceLink CRM user.
  Marketer: 'marketer',
  // Clinical nurse — clinical / telehealth / EVV access.
  Nurse: 'nurse',
  // Caregiver — limited field access.
  Caregiver: 'caregiver',
  // Generic representative — scaffold default.
  Rep: 'rep',
} as const;

export type Role = (typeof Role)[keyof typeof Role];

export const ALL_ROLES: readonly Role[] = [
  Role.SuperAdmin,
  Role.Admin,
  Role.Owner,
  Role.Manager,
  Role.Marketer,
  Role.Nurse,
  Role.Caregiver,
  Role.Rep,
];
