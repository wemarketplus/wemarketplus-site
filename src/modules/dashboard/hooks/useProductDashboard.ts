import { useAppSelector } from '@/app/hooks';
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
// (GET /dashboard/summary). Product still comes from the auth slice so the
// tiles are labeled correctly; the numbers are the tenant's real aggregates.
// Defaults to HospiceLink until the backend ships product on /auth/me.
export function useProductDashboard(): ProductDashboard {
  const product = useAppSelector((s) => s.auth.user?.product) ?? Product.HospiceLink;
  const { data, isLoading, isError } = useGetDashboardSummaryQuery();

  const stats = data ? mapSummaryToStats(data, product) : [];
  const activity = data ? mapSummaryToActivity(data) : [];

  return { product, stats, activity, isLoading, isError };
}
