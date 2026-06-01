import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';

interface PublicRouteProps {
  children: ReactNode;
}

// Use on the login/register screens to bounce already-signed-in users home.
export function PublicRoute({ children }: PublicRouteProps) {
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);
  if (isAuthenticated) return <Navigate to="/" replace />;
  return <>{children}</>;
}
