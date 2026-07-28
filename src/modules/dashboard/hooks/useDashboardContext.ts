import { useAppSelector } from '@/app/hooks';
import { useActiveEntitlement } from '@/modules/access';

// Subscription states that represent a live, paid (or trialing) plan. Anything
// else — most importantly 'incomplete' for a fresh signup that hasn't checked
// out — means the tenant has no active plan yet, so we don't advertise a tier.
const ACTIVE_PLAN_STATUSES = new Set(['active', 'trialing', 'past_due']);

// Bundles the tenant context the dashboard header needs: organization name,
// current product, tier badge, and whether the plan is actually live. Product/
// tier/status follow the ACTIVE dashboard (so the header retitles when a
// dual-product user switches); organizationName comes from the authenticated
// user. Falls back only to neutral defaults so a tenant never sees another
// tenant's name.
export function useDashboardContext() {
  const organizationName = useAppSelector(
    (s) => s.auth.user?.organizationName ?? 'Your organization',
  );
  const { product, tier, subscriptionStatus } = useActiveEntitlement();
  // Only treat the tier as a real plan when billing says so. A brand-new,
  // unpaid tenant is 'incomplete' — it must not display a "PRO" plan pill.
  const hasActivePlan = ACTIVE_PLAN_STATUSES.has(subscriptionStatus ?? '');

  const period = new Date().toLocaleDateString('en-US', {
    month: 'long',
    year: 'numeric',
  });

  return { product, tier, organizationName, period, hasActivePlan };
}
