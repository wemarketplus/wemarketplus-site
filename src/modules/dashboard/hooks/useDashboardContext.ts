import { useAppSelector } from '@/app/hooks';
import { Product, normalizeTier, Tier } from '@/shared/types';

// Subscription states that represent a live, paid (or trialing) plan. Anything
// else — most importantly 'incomplete' for a fresh signup that hasn't checked
// out — means the tenant has no active plan yet, so we don't advertise a tier.
const ACTIVE_PLAN_STATUSES = new Set(['active', 'trialing', 'past_due']);

// Bundles the tenant context the dashboard header needs: organization name,
// current product, tier badge, and whether the plan is actually live — all
// sourced from the authenticated user (/auth/me and login ship
// organizationName/product/tier/subscriptionStatus). Falls back only to neutral
// defaults so a tenant never sees another tenant's name.
export function useDashboardContext() {
  const user = useAppSelector((s) => s.auth.user);
  const product: Product = user?.product ?? Product.HospiceLink;
  const tier: Tier = normalizeTier(user?.tier) ?? Tier.Pro;
  const organizationName = user?.organizationName ?? 'Your organization';
  // Only treat the tier as a real plan when billing says so. A brand-new,
  // unpaid tenant is 'incomplete' — it must not display a "PRO" plan pill.
  const hasActivePlan = ACTIVE_PLAN_STATUSES.has(
    user?.subscriptionStatus ?? '',
  );

  const period = new Date().toLocaleDateString('en-US', {
    month: 'long',
    year: 'numeric',
  });

  return { product, tier, organizationName, period, hasActivePlan };
}
