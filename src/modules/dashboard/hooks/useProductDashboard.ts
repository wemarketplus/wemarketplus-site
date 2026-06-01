import { useAppSelector } from '@/app/hooks';
import { Product } from '@/shared/types';
import {
  ACTIVITY_BY_PRODUCT,
  STATS_BY_PRODUCT,
} from '../constants/dashboardConstants';

// Picks the right stat tiles + activity feed for the user's current product.
// Defaults to HospiceLink until the backend ships product on /auth/me.
export function useProductDashboard() {
  const product = useAppSelector((s) => s.auth.user?.product) ?? Product.HospiceLink;
  return {
    product,
    stats: STATS_BY_PRODUCT[product],
    activity: ACTIVITY_BY_PRODUCT[product],
  };
}
