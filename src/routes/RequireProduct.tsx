import { useEffect, useRef, type ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import { hasProductAccess, useActiveProduct } from '@/modules/access';
import type { Product } from '@/shared/types';

interface RequireProductProps {
  children: ReactNode;
  product: Product;
}

/**
 * Route-level product binding. Two jobs, and only two:
 *
 *  1. ALIGN — arriving on a product's route (a deep link, a bookmark) switches
 *     the active dashboard to that product, so the sidebar and tier gating match
 *     what is being rendered.
 *  2. RELEASE — using the switcher while standing on this product's route sends
 *     the user to `/`, the one route both dashboards share.
 *
 * It is no longer an access gate. `hasProductAccess` is true for both products
 * for every authenticated user (mirroring the backend ProductGuard), so the
 * redirect below only fires when there is no session at all — and the outer
 * ProtectedRoute has already sent that case to /login. Role and tier gating for
 * these routes lives where it always did: ProtectedRoute's `allow`,
 * RequireEntitlement's `minTier`, RequireRoleAtTier, and the backend guards.
 */
export function RequireProduct({ children, product }: RequireProductProps) {
  const user = useAppSelector((s) => s.auth.user);
  const { activeProduct, changeProduct } = useActiveProduct();
  const canOpen = hasProductAccess(user, product);

  // Read the active product WITHOUT subscribing the alignment effect to it.
  const activeProductRef = useRef(activeProduct);
  activeProductRef.current = activeProduct;

  // Which route-product this mount has already aligned for. Guarantees the
  // alignment happens AT MOST ONCE per product per mount, no matter how many
  // times the effect is re-invoked.
  const alignedForRef = useRef<Product | null>(null);

  /**
   * Align the active dashboard to the route ON ARRIVAL — a deep link into a
   * product's page should switch the sidebar and tier gating to match what is
   * being viewed.
   *
   * `activeProduct` is deliberately NOT a dependency. With it in the list this
   * effect re-fired the moment anything else changed the active product, which
   * made it a permanent enforcer rather than an arrival-time alignment: using
   * the product switcher while standing on a product-specific route (say
   * /hl-leads) dispatched the new product, this effect immediately saw
   * `activeProduct !== product` and dispatched it straight back, and the switch
   * silently reverted. Switching only appeared to work from `/`, which is the
   * one dashboard route with no product gate.
   *
   * Aligning once per mount is the actual requirement. What happens AFTER the
   * alignment is handled below, at render, by `switchedAway`.
   */
  useEffect(() => {
    if (!canOpen) return;
    // Already aligned for this route's product on this mount — do nothing. This
    // guard is what makes the effect immune to its own dependencies churning:
    // `changeProduct` is a useCallback over `[dispatch, user]`, so ANY refetch
    // that replaces the user object gives it a new identity and re-runs this
    // effect. Without the guard that re-run would see the freshly-switched
    // product, decide it "disagreed" with the route, and snap it back — the
    // switch reverting a beat after the user made it.
    if (alignedForRef.current === product) return;
    alignedForRef.current = product;
    if (activeProductRef.current !== product) {
      changeProduct(product);
    }
  }, [canOpen, product, changeProduct]);

  if (!canOpen) {
    return <Navigate to="/" replace />;
  }

  /**
   * The user switched dashboards while standing on THIS product's route.
   *
   * Before the alignment above has run, a disagreement just means "arriving" —
   * that is the deep-link case, and the effect resolves it by moving the active
   * product to the route. Once this mount HAS aligned, the only thing that can
   * make them disagree again is a deliberate change from the switcher, and
   * staying here would render one product's page under the other product's
   * sidebar (or bounce the selection straight back).
   *
   * Doing it here rather than in the switcher is what keeps the redirect
   * PROPORTIONATE: the router already knows which routes belong to which
   * product, because it wraps them in this guard. Shared routes — /my-profile,
   * /contacts, /companies, /documents, /notifications, /settings, /billing,
   * /users — sit outside both product groups, so nothing here runs and the user
   * simply stays where they are. The switcher used to navigate to `/`
   * unconditionally, which threw away the current page even when it was
   * perfectly valid for both dashboards.
   */
  const switchedAway =
    alignedForRef.current === product && activeProduct !== product;
  if (switchedAway) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
