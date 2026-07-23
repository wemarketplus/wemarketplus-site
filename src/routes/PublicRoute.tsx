import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';

interface PublicRouteProps {
  children: ReactNode;
  allowAuthenticated?: boolean;
}

// Use on the login/register screens to bounce already-signed-in users home.
// Some public flows such as invite acceptance should stay reachable even when
// the browser already has an authenticated session from another context.
export function PublicRoute({ children, allowAuthenticated = false }: PublicRouteProps) {
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);
  if (isAuthenticated && !allowAuthenticated) return <Navigate to="/" replace />;
  return <>{children}</>;
}
