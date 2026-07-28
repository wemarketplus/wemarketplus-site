import { useActiveProduct } from '@/modules/access';
import { Product } from '@/shared/types';
import { useGetDashboardSummaryQuery } from '../api/dashboardApi';
import type { DashboardActivityItem, DashboardStatCard } from '../types/dashboardTypes';
import { mapSummaryToActivity, mapSummaryToStats } from '../utils/dashboardMapper';

interface ProductDashboard {
  product: Product;
  stats: DashboardStatCard[];
  activity: DashboardActivityItem[];
  isLoading: boolean;
  isError: boolean;
}

// Feeds the dashboard tiles + activity feed from the live tenant summary
// (GET /dashboard/summary). Product follows the ACTIVE dashboard so a
// dual-product user's home retitles when they switch; the numbers are the
// tenant's real aggregates.
export function useProductDashboard(): ProductDashboard {
  const { activeProduct: product } = useActiveProduct();
  const { data, isLoading, isError } = useGetDashboardSummaryQuery();

  const stats = data ? mapSummaryToStats(data, product) : [];
  const activity = data ? mapSummaryToActivity(data) : [];

  return { product, stats, activity, isLoading, isError };
}
