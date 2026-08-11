import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import { CHANGE_PASSWORD_PATH } from '@/shared/constants/routeConstants';
import { RoleGate, type Role } from '@/shared/rbac';

interface ProtectedRouteProps {
  children: ReactNode;
  // Optional role gate. Omit to allow any authenticated user.
  allow?: readonly Role[];
  /**
   * Lets this route render for a user who still owes a password change. Mirrors the
   * backend's `@AllowPasswordChangePending()` decorator, and exists for the same
   * single reason: the change-password screen itself is inside the authenticated
   * area, so without an exemption the redirect below would point at a route that
   * redirects to itself.
   *
   * Do not set this on anything else. It is the way OUT of the lock, not a way
   * around it — and it buys nothing anyway, since the API refuses every other
   * endpoint for such a user regardless of what the client renders.
   */
  allowPasswordChangePending?: boolean;
}

export function ProtectedRoute({
  children,
  allow,
  allowPasswordChangePending = false,
}: ProtectedRouteProps) {
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);
  const mustChangePassword = useAppSelector(
    (s) => s.auth.user?.mustChangePassword ?? false,
  );
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  /**
   * An admin-issued password buys exactly one screen: the one that replaces it.
   *
   * Checked before the role gate on purpose. A locked-out user who deep-links to a
   * screen their role also cannot see should be told to change their password —
   * bouncing them to "/" for the role instead would send them somewhere that is
   * itself blocked, and they would never learn the actual reason.
   */
  if (mustChangePassword && !allowPasswordChangePending) {
    return <Navigate to={CHANGE_PASSWORD_PATH} replace />;
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
