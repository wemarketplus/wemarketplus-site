import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import { RoleGate, type Role } from '@/shared/rbac';

interface ProtectedRouteProps {
  children: ReactNode;
  // Optional role gate. Omit to allow any authenticated user.
  allow?: readonly Role[];
}

export function ProtectedRoute({ children, allow }: ProtectedRouteProps) {
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  if (allow) {
    return (
      <RoleGate
        allow={allow}
        fallback={<Navigate to="/" replace />}
      >
        {children}
      </RoleGate>
    );
  }

  return <>{children}</>;
}
