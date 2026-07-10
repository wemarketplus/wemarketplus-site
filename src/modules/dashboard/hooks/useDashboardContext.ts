import { useAppSelector } from '@/app/hooks';
import { Product, normalizeTier, Tier } from '@/shared/types';

// Bundles the tenant context the dashboard header needs: organization name,
// current product, and tier badge — all sourced from the authenticated user
// (/auth/me and login ship organizationName/product/tier). Falls back only to
// neutral defaults so a tenant never sees another tenant's name.
export function useDashboardContext() {
  const user = useAppSelector((s) => s.auth.user);
  const product: Product = user?.product ?? Product.HospiceLink;
  const tier: Tier = normalizeTier(user?.tier) ?? Tier.Pro;
  const organizationName = user?.organizationName ?? 'Your organization';

  const period = new Date().toLocaleDateString('en-US', {
    month: 'long',
    year: 'numeric',
  });

  return { product, tier, organizationName, period };
}
