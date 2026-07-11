import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import {
  Product,
  Tier,
  normalizeTier,
  tierIncludes,
} from '@/shared/types';

interface RequireEntitlementProps {
  children: ReactNode;
  // Minimum plan tier required to reach this route. Compared product-aware
  // (CommunityLink orders tiers Pro<Gold<Max, HospiceLink Pro<Max<Gold).
  minTier: Tier;
}

// Route-level plan gate: nav hiding alone is not access control, so a user who
// types a gated URL directly must still be turned away. When the tenant's tier
// doesn't include `minTier` we send them to /billing to upgrade (the backend
// also answers 402 UPGRADE_REQUIRED on the underlying API, so this is defense in
// depth, not the only line). Mirrors navigationConfig's isNavItemVisible.
export function RequireEntitlement({ children, minTier }: RequireEntitlementProps) {
  const product: Product = useAppSelector(
    (s) => s.auth.user?.product ?? Product.HospiceLink,
  );
  const tier: Tier = normalizeTier(useAppSelector((s) => s.auth.user?.tier)) ?? Tier.Pro;

  if (!tierIncludes(product, tier, minTier)) {
    // Carry the required tier so the billing page can highlight the upgrade.
    return <Navigate to="/billing" replace state={{ upgradeTo: minTier }} />;
  }

  return <>{children}</>;
}
