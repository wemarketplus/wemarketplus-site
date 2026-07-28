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
 */
export function useActiveEntitlement() {
  const user = useAppSelector((s) => s.auth.user);
  const { activeProduct, changeProduct } = useActiveProduct();
  const entitlement = entitlementForProduct(user, activeProduct);
  return {
    product: activeProduct,
    tier: normalizeTier(entitlement?.tier) ?? Tier.Pro,
    rawTier: entitlement?.tier,
    subscriptionStatus: entitlement?.subscriptionStatus,
    changeProduct,
  };
}
