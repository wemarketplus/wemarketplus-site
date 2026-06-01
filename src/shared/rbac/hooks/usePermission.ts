import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { Role } from '../types/permissionTypes';

interface RoleApi {
  role: Role | null;
  is: (role: Role) => boolean;
  isAny: (roles: readonly Role[]) => boolean;
}

// Named `usePermission` to match the scaffold spec's filename, but the backend
// is role-based so the returned API is role-shaped. See ../types/permissionTypes.
export function usePermission(): RoleApi {
  const role = useAppSelector((s) => s.auth.user?.role ?? null);

  return useMemo<RoleApi>(
    () => ({
      role,
      is: (target) => role === target,
      isAny: (targets) => (role ? targets.includes(role) : false),
    }),
    [role],
  );
}

// Friendlier alias used throughout the app.
export const useRole = usePermission;
