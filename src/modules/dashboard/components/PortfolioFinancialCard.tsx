import { formatUsd } from '@/modules/cl-financial/utils/financialFormat';
import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeader } from '@/shared/ui/data-display';
import type {
  DashboardOperations,
  DashboardPortfolio,
} from '../types/dashboardTypes';
import { DashboardCardAction } from './DashboardCardAction';
import { PortfolioMetricRow } from './PortfolioMetricRow';

/**
 * "Financial Overview" — step 2 of the owner's guide: "Click the Ledger button on
 * the Financial Overview card for Rent Roll, Occupancy %, and Pending Referral
 * Fees."
 *
 * Those three rows are therefore fixed and in that order; Available Units follows
 * them because the reference design has it there and it is the number that explains
 * the gap between the rent roll and what the community could bill.
 *
 * Occupancy and Available Units come from `operations`, which is ABSENT below CL
 * Gold. They render as "—" in that case rather than 0%: a Pro tenant has no
 * apartment inventory at all, and "0% occupied" is a false statement about a real
 * community, where "—" is an honest absence. The two money rows always have data.
 *
 * The "Ledger" action is only rendered when the tenant's plan actually includes the
 * Financial Ledger. Below CL Max the module is not reachable, and a button that
 * bounces the owner to the billing page is worse than a card without one — the
 * numbers on it are still the ones they came for.
 */
export function PortfolioFinancialCard({
  portfolio,
  operations,
  canOpenLedger,
}: {
  portfolio: DashboardPortfolio;
  operations: DashboardOperations | undefined;
  canOpenLedger: boolean;
}) {
  const { rentRoll, pendingReferralFees, monthlyRevenue } = portfolio;

  return (
    <Card>
      <CardContent className="pt-6">
        <SectionHeader
          title="Financial overview"
          subtitle={
            monthlyRevenue.entries > 0
              ? `${formatUsd(monthlyRevenue.total)} booked this month`
              : 'No ledger entries logged this month'
          }
          actions={
            canOpenLedger ? (
              <DashboardCardAction
                to="/financial/ledger"
                label="Ledger"
                ariaLabel="Open the financial ledger"
              />
            ) : undefined
          }
        />
        <div>
          <PortfolioMetricRow
            label="Rent roll"
            detail={`${rentRoll.units} revenue-producing unit${rentRoll.units === 1 ? '' : 's'}`}
            value={`${formatUsd(rentRoll.total)}/mo`}
            tone="positive"
          />
          <PortfolioMetricRow
            label="Occupancy"
            value={
              operations ? `${operations.occupancyRate}%` : '—'
            }
            detail={
              operations
                ? `${operations.units.occupied + operations.units.reserved} of ${operations.units.total} units`
                : 'Requires the operations plan'
            }
            tone={
              !operations
                ? 'neutral'
                : operations.occupancyRate >= 85
                  ? 'positive'
                  : 'caution'
            }
          />
          <PortfolioMetricRow
            label="Pending referral fees"
            detail={
              pendingReferralFees.count > 0
                ? `${pendingReferralFees.count} referral${pendingReferralFees.count === 1 ? '' : 's'} on move-in`
                : undefined
            }
            value={formatUsd(pendingReferralFees.total)}
            tone={pendingReferralFees.total > 0 ? 'caution' : 'positive'}
          />
          <PortfolioMetricRow
            label="Available units"
            value={
              operations
                ? `${operations.units.available} unit${operations.units.available === 1 ? '' : 's'}`
                : '—'
            }
            tone="info"
            last
          />
        </div>
      </CardContent>
    </Card>
  );
}
