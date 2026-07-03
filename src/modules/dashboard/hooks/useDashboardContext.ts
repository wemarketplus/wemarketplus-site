import { useAppSelector } from '@/app/hooks';
import { SUBSCRIPTION_FIXTURE } from '@/shared/fixtures';
import { Product, normalizeTier, type Tier } from '@/shared/types';

// Bundles the tenant context the dashboard header needs: organization name,
// current product, and tier badge. Falls back to the subscription fixture
// when /auth/me doesn't yet ship product/tier (mirrors the live site's
// header pattern: "Sales Dashboard / Sunrise Senior Living — February 2026").
export function useDashboardContext() {
  const user = useAppSelector((s) => s.auth.user);
  const product: Product = user?.product ?? Product.HospiceLink;
  const tier: Tier = normalizeTier(user?.tier) ?? SUBSCRIPTION_FIXTURE.plan;
  const organizationName = SUBSCRIPTION_FIXTURE.organizationName;

  const period = new Date().toLocaleDateString('en-US', {
    month: 'long',
    year: 'numeric',
  });

  return { product, tier, organizationName, period };
}
