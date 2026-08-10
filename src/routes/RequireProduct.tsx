import { useEffect, useRef, type ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useAppSelector } from '@/app/hooks';
import { hasProductAccess, useActiveProduct } from '@/modules/access';
import type { Product } from '@/shared/types';

interface RequireProductProps {
  children: ReactNode;
  product: Product;
}

// Route-level product gate: a user not entitled to `product` cannot reach this
// route even by typing the URL. Mirrors the backend ProductGuard (which answers
// 403 on the underlying API), so this is defense in depth plus a clean redirect
// rather than a raw error. Authentication is handled by the outer
// ProtectedRoute; here we only decide product access.
export function RequireProduct({ children, product }: RequireProductProps) {
  const user = useAppSelector((s) => s.auth.user);
  const { activeProduct, changeProduct } = useActiveProduct();
  const entitled = hasProductAccess(user, product);

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
    if (!entitled) return;
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
  }, [entitled, product, changeProduct]);

  if (!entitled) {
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
