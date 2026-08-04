import { useAppSelector } from '@/app/hooks';
import { Tier, normalizeTier } from '@/shared/types';
import { entitlementForProduct } from '../utils/productAccess';
import { useActiveProduct } from './useActiveProduct';

/**
 * The active dashboard's product together with ITS OWN tier and billing status
 * (not the tenant's primary-product tier). This is what every product-aware
 * surface should read — the sidebar, the tier route guards, and the dashboard
 * home — so a dual-product user viewing CommunityLink is gated by their
 * CommunityLink tier even if their primary product is HospiceLink.
 *
 * `tier` is the normalized UI Tier (defaults to Pro); `rawTier` is the raw
 * backend value; `changeProduct` switches the active dashboard.
 *
 * `isResolved` says whether the entitlement actually came from the server rather
 * than from the Pro fallback. Route guards MUST wait for it: on a hard navigation the
 * app boots from the persisted store, so a Gold tenant briefly looks like Pro and a
 * tier guard that decides immediately bounces them to /billing before /auth/me
 * answers. That was observed as a false redirect on a genuinely entitled tenant.
 */
export function useActiveEntitlement() {
  const user = useAppSelector((s) => s.auth.user);
  const { activeProduct, changeProduct } = useActiveProduct();
  const entitlement = entitlementForProduct(user, activeProduct);
  return {
    product: activeProduct,
    tier: normalizeTier(entitlement?.tier) ?? Tier.Pro,
    // An entitlement row for the active product, carrying a tier we recognise, is
    // the only proof the real plan is known. Absent that, callers must not decide.
    isResolved: normalizeTier(entitlement?.tier) !== undefined,
    rawTier: entitlement?.tier,
    subscriptionStatus: entitlement?.subscriptionStatus,
    changeProduct,
  };
}
