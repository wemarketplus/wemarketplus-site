import { ALL_ROLES, ROLE_LABELS, Role } from '@/shared/rbac';
import type { PillProps } from '@/shared/ui/data-display';

// Mirrors wemarketplus-backend/src/users/users.constants.ts.
export const PASSWORD_MIN_LENGTH = 8;
export const NAME_MIN_LENGTH = 1;
export const NAME_MAX_LENGTH = 120;
export const PHONE_MAX_LENGTH = 40;

// Backend caps `limit` at 100 (see common/dto/pagination.dto.ts). We pick a
// sensible default page size for the UI table.
export const DEFAULT_PAGE_SIZE = 20;

export const USERS_TAGS = {
  List: 'Users.List',
  Detail: 'Users.Detail',
  // The tenant's calendar-colour map. Its own tag (not List) because the two
  // have different audiences: every role reads the colour map, only staff read
  // the user list, so a Marketer saving a colour must be able to refresh the
  // calendar without invalidating a list they were never allowed to fetch.
  CalendarColors: 'Users.CalendarColors',
} as const;

// Pastel pill tone per role (matching crm-*.html .pill-*).
export const ROLE_PILL: Record<Role, PillProps['tone']> = {
  [Role.SuperAdmin]: 'r',
  [Role.Admin]: 'p',
  [Role.Owner]: 'gd',
  [Role.Manager]: 'b',
  [Role.Marketer]: 'g',
  [Role.Nurse]: 'y',
  [Role.Caregiver]: 'b',
  [Role.Rep]: 'b',
  [Role.Director]: 'p',
  [Role.SalesAdmissions]: 'g',
  [Role.OwnerInvestor]: 'gd',
  [Role.Maintenance]: 'b',
  [Role.Housekeeping]: 'b',
};

// Roles a tenant admin may assign when creating a user — mirrors the backend
// CreateUserDto whitelist. SuperAdmin is platform-only and must NEVER be
// offered here.
export const ASSIGNABLE_ROLES = [
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
] as const;

// Friendly-labelled options for the role <Select> in the Add User form.
export const ASSIGNABLE_ROLE_OPTIONS: ReadonlyArray<{ value: Role; label: string }> =
  ASSIGNABLE_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }));

// Role filter chips for the users list — "All" plus one chip per role.
export const ROLE_FILTER_CHIPS: ReadonlyArray<{ value: Role | 'all'; label: string }> = [
  { value: 'all', label: 'All roles' },
  ...ALL_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] })),
];
