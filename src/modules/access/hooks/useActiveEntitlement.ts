import { useAppSelector } from '@/app/hooks';
import { authApi } from '@/modules/auth/api/authApi';
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
 * `tier` is the normalized UI Tier; `rawTier` is the raw backend value;
 * `changeProduct` switches the active dashboard.
 *
 * BASE-TIER FALLBACK. Every authenticated user can open either dashboard, so the
 * active product may be one the tenant holds no entitlement for. That opens at
 * the product's BASE tier (Pro, the lowest rank for both products): the shared
 * and Pro-level modules work, and everything tier-gated above Pro stays hidden
 * and unreachable — which is exactly what the backend does too, since TierGuard
 * finds no entitlement for that product and answers 402 UPGRADE_REQUIRED.
 * `subscriptionStatus` stays undefined, so the sidebar prints no plan pill for a
 * dashboard the tenant isn't paying for.
 *
 * `isResolved` says whether the plan is actually known rather than assumed.
 * Route guards MUST wait for it: on a hard navigation the app boots from the
 * persisted store, so a Gold tenant briefly looks like Pro and a tier guard that
 * decides immediately bounces them to /billing before /auth/me answers. That was
 * observed as a false redirect on a genuinely entitled tenant. An entitlement row
 * carrying a tier we recognise resolves it immediately; the base-tier fallback
 * only counts as resolved once /auth/me has actually answered, so a persisted
 * user that predates a newly granted entitlement still can't trigger that
 * redirect. `useQueryState` READS the /auth/me cache entry ProfileSync owns — it
 * subscribes without issuing a request of its own.
 */
export function useActiveEntitlement() {
  const user = useAppSelector((s) => s.auth.user);
  const { activeProduct, changeProduct } = useActiveProduct();
  const { isSuccess: isProfileFresh } =
    authApi.endpoints.me.useQueryState(undefined);
  const entitlement = entitlementForProduct(user, activeProduct);
  const entitledTier = normalizeTier(entitlement?.tier);
  return {
    product: activeProduct,
    tier: entitledTier ?? Tier.Pro,
    isResolved: entitledTier !== undefined || isProfileFresh,
    rawTier: entitlement?.tier,
    subscriptionStatus: entitlement?.subscriptionStatus,
    changeProduct,
  };
}
