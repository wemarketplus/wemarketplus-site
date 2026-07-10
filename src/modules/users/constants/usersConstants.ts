import { ALL_ROLES, ROLE_LABELS, Role } from '@/shared/rbac';
import type { PillProps } from '@/shared/ui/data-display';

// Mirrors wemarketplus-backend/src/users/users.constants.ts.
export const PASSWORD_MIN_LENGTH = 8;
export const NAME_MIN_LENGTH = 1;
export const NAME_MAX_LENGTH = 120;

// Backend caps `limit` at 100 (see common/dto/pagination.dto.ts). We pick a
// sensible default page size for the UI table.
export const DEFAULT_PAGE_SIZE = 20;

export const USERS_TAGS = {
  List: 'Users.List',
  Detail: 'Users.Detail',
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
] as const;

// Friendly-labelled options for the role <Select> in the Add User form.
export const ASSIGNABLE_ROLE_OPTIONS: ReadonlyArray<{ value: Role; label: string }> =
  ASSIGNABLE_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }));

// Role filter chips for the users list — "All" plus one chip per role.
export const ROLE_FILTER_CHIPS: ReadonlyArray<{ value: Role | 'all'; label: string }> = [
  { value: 'all', label: 'All roles' },
  ...ALL_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] })),
];
