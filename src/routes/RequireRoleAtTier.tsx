import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import { RoleGate, type Role } from '@/shared/rbac';
import { Product, Tier, normalizeTier, tierIncludes } from '@/shared/types';

interface TierRoleWindow {
  minTier: Tier;
  // Upper bound (inclusive) — omit for no upper bound.
  maxTier?: Tier;
  allow: readonly Role[];
}

interface RequireRoleAtTierProps {
  children: ReactNode;
  // Windows are checked in order; the first whose [minTier, maxTier] contains
  // the tenant's tier wins and its `allow` list gates the route.
  windows: readonly TierRoleWindow[];
}

// Route-level guard for the rare nav item whose allowed-role-set changes by
// tier band (e.g. Occupancy Overview: Director-only at Gold, broader at Max)
// — a single ProtectedRoute `allow` list can't express that. Mirrors the same
// windowed-NavItem pattern already used in navigationConfig.tsx: if the
// tenant's tier doesn't fall in any window, redirect to /billing (upgrade);
// if it does but the role isn't in that window's `allow`, redirect home —
// same fallbacks as RequireEntitlement/ProtectedRoute individually.
export function RequireRoleAtTier({ children, windows }: RequireRoleAtTierProps) {
  const location = useLocation();
  const product: Product = useAppSelector((s) => s.auth.user?.product ?? Product.HospiceLink);
  const tier: Tier = normalizeTier(useAppSelector((s) => s.auth.user?.tier)) ?? Tier.Pro;
  const isAuthenticated = useAppSelector((s) => s.auth.isAuthenticated);

  if (!isAuthenticated) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }

  const active = windows.find(
    (w) =>
      tierIncludes(product, tier, w.minTier) &&
      (!w.maxTier || tierIncludes(product, w.maxTier, tier)),
  );

  if (!active) {
    const lowestMinTier = windows[0]?.minTier;
    return <Navigate to="/billing" replace state={{ upgradeTo: lowestMinTier }} />;
  }

  return (
    <RoleGate allow={active.allow} fallback={<Navigate to="/" replace />}>
      {children}
    </RoleGate>
  );
}
