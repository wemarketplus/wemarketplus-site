import { Role } from '@/shared/rbac';
import type { RoleCapability } from '../types/permissionsTypes';

// Static, hand-authored matrix that mirrors what the backend enforces in
// `wemarketplus-backend/src/users/users.controller.ts` and
// `src/auth/auth.controller.ts`. Keep in sync if route guards change.
export const ROLE_CAPABILITIES: readonly RoleCapability[] = [
  {
    role: Role.Admin,
    description: 'Full access. Manages users, organization settings, and policies.',
    capabilities: [
      'Create, edit, and delete users',
      'Promote and demote roles',
      'View the full team directory',
      'Access all administrative screens',
    ],
  },
  {
    role: Role.Manager,
    description: 'Day-to-day team management without destructive permissions.',
    capabilities: [
      'View the full team directory',
      'View individual user profiles',
      'Cannot create, edit, or delete users',
    ],
  },
  {
    role: Role.Rep,
    description: 'Individual contributor. Can only see and edit themselves.',
    capabilities: [
      'View and edit own profile',
      'Cannot access the user directory',
    ],
  },
];

export const PERMISSIONS_TAGS = {
  List: 'Permissions.List',
} as const;
