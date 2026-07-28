import { useEffect, type ReactNode } from 'react';
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
//
// When an entitled user deep-links into a product's route while a different
// dashboard is active, we align the active product to the route so the sidebar
// and tier gating match what they're viewing.
export function RequireProduct({ children, product }: RequireProductProps) {
  const user = useAppSelector((s) => s.auth.user);
  const { activeProduct, changeProduct } = useActiveProduct();
  const entitled = hasProductAccess(user, product);

  useEffect(() => {
    if (entitled && activeProduct !== product) {
      changeProduct(product);
    }
  }, [entitled, activeProduct, product, changeProduct]);

  if (!entitled) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
