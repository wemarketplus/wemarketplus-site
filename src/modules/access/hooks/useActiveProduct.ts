import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import type { Product } from '@/shared/types';
import { setActiveProduct } from '../store/accessSlice';
import { hasProductAccess, resolveActiveProduct } from '../utils/productAccess';

/**
 * The currently-active dashboard/product and a setter that switches it. The
 * active product is resolved against the user's entitlements, so it can never
 * be a product the user isn't allowed to use. `changeProduct` ignores requests
 * for products the user has no access to (defence in depth alongside the guard).
 */
export function useActiveProduct() {
  const dispatch = useAppDispatch();
  const user = useAppSelector((s) => s.auth.user);
  const stored = useAppSelector((s) => s.access.activeProduct);
  const activeProduct = resolveActiveProduct(user, stored);

  const changeProduct = useCallback(
    (product: Product) => {
      if (hasProductAccess(user, product)) {
        dispatch(setActiveProduct(product));
      }
    },
    [dispatch, user],
  );

  return { activeProduct, changeProduct };
}
