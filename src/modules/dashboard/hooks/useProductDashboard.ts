import { useActiveEntitlement } from '@/modules/access';
import {
  CL_CARE_ROLES,
  CL_FIELD_ROLES,
  CL_FINANCIAL_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_MANAGEMENT_ROLES,
  Role,
  useRole,
} from '@/shared/rbac';
import { useGetClFieldQueueQuery } from '@/modules/daily-queue';
import { Product, Tier, tierIncludes } from '@/shared/types';
import { useGetDashboardSummaryQuery } from '../api/dashboardApi';
import type {
  DashboardActivityItem,
  DashboardOperations,
  DashboardPortfolio,
  DashboardStatCard,
} from '../types/dashboardTypes';
import { mapSummaryToActivity, mapSummaryToStats } from '../utils/dashboardMapper';
import {
  buildOperationsAlerts,
  type OperationsAlert,
} from '../utils/operationsAlerts';

interface ProductDashboard {
  product: Product;
  stats: DashboardStatCard[];
  activity: DashboardActivityItem[];
  /**
   * Set only for the Executive Dashboard. Undefined otherwise, which is what the
   * page keys the Unit status and Operations alerts cards off.
   */
  operations?: DashboardOperations;
  /**
   * Set only for the Owner/Investor Portfolio Dashboard — the page keys its four
   * portfolio cards off this.
   */
  portfolio?: DashboardPortfolio;
  /**
   * The operations block AS SEEN BY THE OWNER. Separate from `operations` because
   * that field doubles as the "render the executive panels" flag; the owner needs
   * the same numbers for their Maintenance and Unit status cards without turning
   * the director's alert queue on. Undefined for every other persona, and below
   * CL Gold.
   */
  portfolioOperations?: DashboardOperations;
  alerts: OperationsAlert[];
  isLoading: boolean;
  isError: boolean;
}

/**
 * Feeds the dashboard tiles + activity feed from the live tenant summary
 * (GET /dashboard/summary). Product follows the ACTIVE dashboard so a
 * dual-product user's home retitles when they switch; the numbers are the tenant's
 * real aggregates.
 *
 * THE EXECUTIVE VARIANT needs two things to be true at once, and both are resolved
 * here so the page stays presentational:
 *
 *   - the viewer is a CommunityLink MANAGEMENT role — the Executive Director the
 *     guide is written for, plus the admin/owner tier above them;
 *   - the tenant's plan includes OPERATIONS, which the server signals simply by
 *     sending the `operations` block (it omits it below CL Gold).
 *
 * A Marketer on the same Gold tenant keeps the sales tiles. They cannot open
 * Apartment Inventory or Maintenance, so four of the six executive tiles would be
 * numbers they can read and never act on — and every one of those tiles is a link.
 */
export function useProductDashboard(): ProductDashboard {
  // Entitlement, not just product: the tile destinations below are tier-gated,
  // and this is the same per-product tier the routes and the sidebar read.
  const { product, tier } = useActiveEntitlement();
  const { is, isAny } = useRole();
  const { data, isLoading, isError } = useGetDashboardSummaryQuery();

  const isExecutive =
    product === Product.CommunityLink && isAny(CL_MANAGEMENT_ROLES);
  /**
   * The Owner/Investor variant. Keyed off the ROLE plus the server having sent the
   * `portfolio` block — the server omits that block for anyone outside
   * CL_FINANCIAL_ROLES, so this cannot render tiles from data the viewer was not
   * given.
   *
   * Checked as a distinct persona rather than folded into `isExecutive`, which
   * OwnerInvestor also satisfies (it is in CL_MANAGEMENT_ROLES). The two dashboards
   * answer different questions: the director's is operational churn, the owner's is
   * "what did the portfolio earn". `mapSummaryToStats` resolves the overlap in the
   * owner's favour.
   */
  const isPortfolio =
    product === Product.CommunityLink && is(Role.OwnerInvestor);
  const portfolio = isPortfolio ? data?.communitylink?.portfolio : undefined;

  /**
   * The Unit Status + Operations Alerts pair stays EXECUTIVE-ONLY.
   *
   * The owner gets `operations` numbers inside their own tiles and cards, but not
   * these two panels: Operations Alerts is a to-do list ("assign this work order",
   * "this unit has been in make-ready for 9 days") aimed at whoever clears it, and
   * the guide is explicit that the owner wants maintenance visibility "without
   * needing to manage them yourself". Handing them a queue of other people's tasks
   * is the opposite of an at-a-glance portfolio view.
   */
  const operations =
    isExecutive && !isPortfolio ? data?.communitylink?.operations : undefined;

  /**
   * The Nurse/Caregiver variant. Keyed off the care roles plus the server having sent
   * the `care` block, which it computes only for those roles.
   *
   * No overlap with the other two variants: neither care role is a member of any
   * CommunityLink group that reaches the sales, executive or financial surfaces.
   */
  const isCare = product === Product.CommunityLink && isAny(CL_CARE_ROLES);

  /**
   * The field-technician variant — Maintenance and Housekeeping.
   *
   * Their tiles come from /cl/field-queue, not the tenant summary, because what a
   * technician owes is per-USER and the summary is a tenant roll-up. Skipped for
   * every other persona, and below CL Gold: the queue endpoint is tier-gated to the
   * operations bundle, so asking there would only ever earn a 402.
   */
  const isField = product === Product.CommunityLink && isAny(CL_FIELD_ROLES);
  const hasOperations = Boolean(data?.communitylink?.operations);
  const { data: fieldQueueData } = useGetClFieldQueueQuery(undefined, {
    skip: !isField || !hasOperations,
  });
  const fieldQueue = fieldQueueData
    ? {
        totalItems: fieldQueueData.totalItems,
        makeReadyTasks: fieldQueueData.makeReadyTasks.length,
        housekeepingTasks: fieldQueueData.housekeepingTasks.length,
        maintenanceTickets: fieldQueueData.maintenanceTickets.length,
      }
    : undefined;

  /**
   * Tile destinations must satisfy the SAME gates as the routes they point at, or
   * a tile becomes a redirect to /billing (or to "/") dressed as a drill-down.
   *
   *  - Financial Ledger / Revenue Leakage are CL Max.
   *  - Occupancy Overview admits only SuperAdmin + Director in its Gold window and
   *    widens to CL_FINANCIAL_ROLES at Max — so an Owner/Investor reaches it at Max
   *    only. Mirrors navigationConfig's two windowed entries; change one, change
   *    both.
   */
  const canOpenFinancials =
    product === Product.CommunityLink &&
    tierIncludes(Product.CommunityLink, tier, Tier.Max);
  const canOpenOccupancy =
    product === Product.CommunityLink &&
    isAny(CL_FINANCIAL_ROLES) &&
    tierIncludes(Product.CommunityLink, tier, Tier.Max);

  const stats = data
    ? mapSummaryToStats(
        data,
        product,
        isExecutive,
        isPortfolio,
        isCare,
        fieldQueue,
        isField,
        // Which boards this role works — the server already scopes the queue this
        // way, so the tiles must agree or they offer a screen the role cannot open.
        isAny(CL_HOUSEKEEPING_ROLES),
        isAny(CL_MAINTENANCE_ROLES),
        canOpenFinancials,
        canOpenOccupancy,
      )
    : [];
  const activity = data ? mapSummaryToActivity(data) : [];
  const alerts = operations
    ? buildOperationsAlerts(operations, data?.communitylink?.leads.hot ?? 0)
    : [];

  return {
    product,
    stats,
    activity,
    operations,
    portfolio,
    // The owner's cards summarise operations too (open tickets, unit status), so
    // they need the block even though the executive panels above are suppressed.
    portfolioOperations: isPortfolio
      ? data?.communitylink?.operations
      : undefined,
    alerts,
    isLoading,
    isError,
  };
}
