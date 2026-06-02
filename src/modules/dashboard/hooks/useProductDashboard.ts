import { useAppSelector } from '@/app/hooks';
import { Product } from '@/shared/types';
import { getDashboardActivity, getDashboardStats } from '../api/dashboardApi';

// Picks the right stat tiles + activity feed for the user's current product.
// Defaults to HospiceLink until the backend ships product on /auth/me.
export function useProductDashboard() {
  const product = useAppSelector((s) => s.auth.user?.product) ?? Product.HospiceLink;
  return {
    product,
    stats: getDashboardStats(product),
    activity: getDashboardActivity(product),
  };
}
