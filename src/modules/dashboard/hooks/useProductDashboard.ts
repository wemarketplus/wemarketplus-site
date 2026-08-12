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

interface ProductDashboardOptions {
  /**
   * Don't fetch the tenant summary at all.
   *
   * For screens that render none of it — CommunityLink's role-scoped dashboards
   * own their own data — so the request is not merely ignored but never sent.
   * That matters beyond the wasted round trip: /dashboard/summary aggregates
   * prospects, invoices and the audit log, so a role without those entitlements
   * gets a 403 that would put the caller into `isError` and paint a failure
   * banner over a screen that was working. Returns empty stats/activity and
   * `isLoading: false`, which is the honest answer to "we did not ask".
   */
  skip?: boolean;
}

// Feeds the dashboard tiles + activity feed from the live tenant summary
// (GET /dashboard/summary). Product follows the ACTIVE dashboard so a
// dual-product user's home retitles when they switch; the numbers are the
// tenant's real aggregates.
export function useProductDashboard(
  { skip = false }: ProductDashboardOptions = {},
): ProductDashboard {
  const { activeProduct: product } = useActiveProduct();
  const { data, isLoading, isError } = useGetDashboardSummaryQuery(undefined, {
    skip,
  });

  const stats = data ? mapSummaryToStats(data, product) : [];
  const activity = data ? mapSummaryToActivity(data) : [];

  return { product, stats, activity, isLoading, isError };
}
