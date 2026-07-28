import { useAppSelector } from '@/app/hooks';
import type { Product } from '@/shared/types';
import { entitledProducts } from '../utils/productAccess';

/**
 * The products the signed-in user is entitled to. `hasMultiple` is the gate for
 * showing the product switcher — a single-product user never sees it.
 */
export function useEntitlements() {
  const user = useAppSelector((s) => s.auth.user);
  const products = entitledProducts(user);
  return {
    products,
    hasMultiple: products.length > 1,
    has: (product: Product) => products.includes(product),
  };
}
