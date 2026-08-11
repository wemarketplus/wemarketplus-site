import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useActiveEntitlement } from '@/modules/access';
import { Product, Tier, tierIncludes } from '@/shared/types';

/**
 * The tier a route needs.
 *
 * A bare `Tier` is the common case. The per-product map exists because the two
 * products do NOT order their tiers the same way — HospiceLink is
 * Pro<Max<Gold, CommunityLink is Pro<Gold<Max — so a capability sold at the TOP
 * tier of both is `Gold` for one and `Max` for the other. The backend expresses
 * this with a single feature key and a rank (see FEATURE_MIN_RANK in
 * plan-catalog.ts); this is the client-side equivalent for a shared route.
 */
export type RequiredTier = Tier | Partial<Record<Product, Tier>>;

interface RequireEntitlementProps {
  children: ReactNode;
  // Minimum plan tier required to reach this route. Compared product-aware
  // (CommunityLink orders tiers Pro<Gold<Max, HospiceLink Pro<Max<Gold).
  minTier: RequiredTier;
}

/** Resolves the tier requirement for the product the user is currently in. */
const resolveMinTier = (
  minTier: RequiredTier,
  product: Product,
): Tier | undefined =>
  typeof minTier === 'string' ? minTier : minTier[product];

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

  const required = resolveMinTier(minTier, product);

  // A per-product map that names no tier for the ACTIVE product means the route
  // is not sold for that product at all. Send them home rather than to /billing:
  // there is no upgrade that would grant it.
  if (required === undefined) {
    return <Navigate to="/" replace />;
  }

  if (!tierIncludes(product, tier, required)) {
    // Carry the required tier so the billing page can highlight the upgrade.
    return <Navigate to="/billing" replace state={{ upgradeTo: required }} />;
  }

  return <>{children}</>;
}
