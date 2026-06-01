import type { ReactNode } from 'react';
import { usePermission } from '../hooks/usePermission';
import type { Role } from '../types/permissionTypes';

interface PermissionGateProps {
  allow: readonly Role[];
  fallback?: ReactNode;
  children: ReactNode;
}

export function PermissionGate({ allow, fallback = null, children }: PermissionGateProps) {
  const { isAny } = usePermission();
  return <>{isAny(allow) ? children : fallback}</>;
}

// Friendlier alias — same component, role-shaped name.
export const RoleGate = PermissionGate;
