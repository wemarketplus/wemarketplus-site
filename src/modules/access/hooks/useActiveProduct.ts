import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import type { Product } from '@/shared/types';
import { setActiveProduct } from '../store/accessSlice';
import { hasProductAccess, resolveActiveProduct } from '../utils/productAccess';

/**
 * The currently-active dashboard/product and a setter that switches it.
 *
 * `changeProduct` succeeds for BOTH dashboards for any authenticated user — that
 * is what makes the switcher work for every logged-in user regardless of role or
 * entitlement. It still refuses when there is no session (`hasProductAccess`
 * returns false with no user), so nothing can select a dashboard before login.
 *
 * The switch is a single reducer on the access slice: no token is touched, no
 * request re-issued, no navigation to /login. The user stays exactly as
 * authenticated as they were a moment before.
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
