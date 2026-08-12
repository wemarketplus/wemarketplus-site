import {
  Activity,
  DoorOpen,
  Flame,
  GitBranch,
  PieChart,
  Receipt,
  TrendingUp,
  Wrench,
} from 'lucide-react';
import { useActiveEntitlement } from '@/modules/access';
import { StatTile } from '@/shared/ui/data-display';
import { Product, Tier, tierIncludes } from '@/shared/types';
import { useClPortfolioDashboard } from '../hooks/useClPortfolioDashboard';
import {
  formatClCurrency,
  formatClPercent,
} from '../utils/clDashboardMetrics';
import { ClDashboardState } from './ClDashboardState';
import { ClPortfolioCard } from './ClPortfolioCard';

/**
 * The Owner/Investor Portfolio Dashboard — "the financial and occupancy picture
 * at a glance, without needing to dig through individual tabs."
 *
 * Two bands, matching how the guide describes the screen: the six-figure top row
 * it lists in Step 1, then the action cards (Financial Overview → Ledger, Revenue
 * Leakage → View, Maintenance → View, Referral Pipeline → Full Pipeline) it walks
 * through in Steps 2–5.
 */
export function ClPortfolioDashboard() {
  const {
    occupancy,
    monthlyRevenue,
    pendingFees,
    hotLeads,
    openWorkOrders,
    vacancyExposure,
    isLoading,
    isError,
  } = useClPortfolioDashboard();

  /**
   * The deep financial screens are Max-tier (see COMMUNITYLINK_FINANCIAL in
   * navigationConfig and the matching route guards). Checked here so a Gold owner
   * gets the summary figure with an honest note instead of a button that
   * RequireEntitlement would bounce.
   */
  const { tier } = useActiveEntitlement();
  const hasFinancials = tierIncludes(Product.CommunityLink, tier, Tier.Max);

  if (isLoading || isError) {
    return <ClDashboardState isError={isError} />;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <StatTile
          label="Occupancy rate"
          value={formatClPercent(occupancy.rate)}
          hint={`${occupancy.occupied} of ${occupancy.total} units filled`}
          tone={occupancy.rate >= 0.9 ? 'g' : 'y'}
          icon={PieChart}
        />
        <StatTile
          label="Available units"
          value={String(occupancy.available)}
          hint="Ready to move in"
          tone="b"
          icon={DoorOpen}
        />
        <StatTile
          label="Monthly revenue"
          value={formatClCurrency(monthlyRevenue)}
          hint="Rent from filled units"
          tone="g"
          icon={TrendingUp}
        />
        <StatTile
          label="Pending referral fees"
          value={formatClCurrency(pendingFees.amount)}
          hint={`${pendingFees.count} unpaid referral${pendingFees.count === 1 ? '' : 's'}`}
          tone={pendingFees.count > 0 ? 'y' : 'g'}
          icon={Receipt}
        />
        <StatTile
          label="Hot leads"
          value={String(hotLeads)}
          hint={hotLeads > 0 ? 'Flagged urgent' : 'None flagged'}
          tone={hotLeads > 0 ? 'r' : 'g'}
          icon={Flame}
        />
        <StatTile
          label="Open work orders"
          value={String(openWorkOrders)}
          hint={openWorkOrders > 0 ? 'In the maintenance queue' : 'All clear'}
          tone={openWorkOrders > 0 ? 'r' : 'g'}
          icon={Wrench}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <ClPortfolioCard
          title="Financial overview"
          icon={TrendingUp}
          value={formatClCurrency(monthlyRevenue)}
          detail={`Rent roll · ${formatClPercent(occupancy.rate)} occupancy · ${formatClCurrency(pendingFees.amount)} fees pending`}
          actionLabel="Ledger"
          to={hasFinancials ? '/financial/ledger' : null}
        />
        <ClPortfolioCard
          title="Revenue leakage"
          icon={Activity}
          value={formatClCurrency(vacancyExposure)}
          detail={`Left on the table by ${occupancy.available} vacant unit${occupancy.available === 1 ? '' : 's'} each month`}
          actionLabel="View"
          to={hasFinancials ? '/financial/leakage' : null}
        />
        <ClPortfolioCard
          title="Maintenance"
          icon={Wrench}
          value={String(openWorkOrders)}
          detail="Open tickets — a read-only view; the team manages them"
          actionLabel="View"
          to="/operations/maintenance"
        />
        <ClPortfolioCard
          title="Referral pipeline"
          icon={GitBranch}
          value={String(pendingFees.count)}
          detail="Paid referrals awaiting a fee — paid vs organic sources"
          actionLabel="Full pipeline"
          to={hasFinancials ? '/referral-pipeline' : null}
        />
      </div>
    </div>
  );
}
