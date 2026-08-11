import { useAppSelector } from '@/app/hooks';
import type { Product } from '@/shared/types';
import { entitledProducts, switchableProducts } from '../utils/productAccess';

/**
 * The dashboards the signed-in user can switch between (`products`) alongside
 * the ones the tenant is actually billed for (`entitled`).
 *
 * `products` is BOTH dashboards for every authenticated user — one login, one
 * session, either dashboard. It used to be the entitlement list, which is why a
 * single-product tenant got no switcher at all: `hasMultiple` was false and the
 * control returned null. `hasMultiple` is kept for callers that want to know
 * whether switching is even a thing (it is, for any session).
 *
 * `entitled` / `isEntitledTo` remain the PLAN question — read those, never
 * `products`, when deciding tier/feature access or what billing should show.
 */
export function useEntitlements() {
  const user = useAppSelector((s) => s.auth.user);
  const products = switchableProducts(user);
  const entitled = entitledProducts(user);
  return {
    products,
    hasMultiple: products.length > 1,
    has: (product: Product) => products.includes(product),
    entitled,
    isEntitledTo: (product: Product) => entitled.includes(product),
  };
}
