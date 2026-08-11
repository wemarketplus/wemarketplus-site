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
  // CommunityLink operational roles (see backend roles.enum.ts).
  Director: 'director',
  SalesAdmissions: 'sales_admissions',
  OwnerInvestor: 'owner_investor',
  Maintenance: 'maintenance',
  Housekeeping: 'housekeeping',
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
  Role.Director,
  Role.SalesAdmissions,
  Role.OwnerInvestor,
  Role.Maintenance,
  Role.Housekeeping,
];

/**
 * A tenant-defined job title with the sidebar tabs it shows. Mirrors the backend
 * CustomRoleResponseDto (wemarketplus-backend/src/custom-roles).
 *
 * `baseRole` is the role whose PERMISSIONS the holder actually has — the user's own
 * `role` field always equals it, and every guard reads that. `navKeys` only NARROWS
 * the menu (see isNavItemVisible), so a custom role can never grant anything its
 * base role lacks.
 */
export interface CustomRole {
  id: string;
  name: string;
  baseRole: Role;
  navKeys: string[];
  isActive: boolean;
  /** Present on the admin list only — how many users hold this role. */
  memberCount?: number;
}
