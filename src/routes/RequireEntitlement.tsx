import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useActiveEntitlement } from '@/modules/access';
import { Tier, tierIncludes } from '@/shared/types';

interface RequireEntitlementProps {
  children: ReactNode;
  // Minimum plan tier required to reach this route. Compared product-aware
  // (CommunityLink orders tiers Pro<Gold<Max, HospiceLink Pro<Max<Gold).
  minTier: Tier;
}

// Route-level plan gate: nav hiding alone is not access control, so a user who
// types a gated URL directly must still be turned away. Tier is read for the
// ACTIVE product (a dual-product user is gated by whichever dashboard they're
// viewing). When the tier doesn't include `minTier` we send them to /billing to
// upgrade (the backend also answers 402 UPGRADE_REQUIRED on the underlying API,
// so this is defense in depth). Mirrors navigationConfig's isNavItemVisible.
export function RequireEntitlement({ children, minTier }: RequireEntitlementProps) {
  const { product, tier, isResolved } = useActiveEntitlement();

  // Do not decide before the real plan is known. The store rehydrates from
  // redux-persist first, so on a hard navigation an entitled tenant momentarily
  // reads as the Pro fallback — deciding here would redirect them to /billing for a
  // route they are entitled to, and the redirect is not undone once /auth/me lands.
  if (!isResolved) return null;

  if (!tierIncludes(product, tier, minTier)) {
    // Carry the required tier so the billing page can highlight the upgrade.
    return <Navigate to="/billing" replace state={{ upgradeTo: minTier }} />;
  }

  return <>{children}</>;
}
