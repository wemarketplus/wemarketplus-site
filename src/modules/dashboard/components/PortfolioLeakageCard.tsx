import { formatUsd } from '@/modules/cl-financial/utils/financialFormat';
import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeader } from '@/shared/ui/data-display';
import type { DashboardPortfolio } from '../types/dashboardTypes';
import { DashboardCardAction } from './DashboardCardAction';
import { PortfolioMetricRow } from './PortfolioMetricRow';

/**
 * "Revenue Leakage" — step 3: "Click View on the Revenue Leakage card to see
 * dollars you're leaving on the table from vacant units."
 *
 * TWO DISTINCT FIGURES, deliberately not added together into one headline.
 *
 *   - VACANT UNITS is the guide's own framing: rent forgone on units sitting
 *     empty, summed from each unit's own `monthlyRate` server-side.
 *   - TRACKED ISSUES is the Revenue Leakage module's log — concessions never
 *     rescinded, under-market renewals, uncollected fees.
 *
 * They overlap conceptually but not in the data, and summing them would double-count
 * any vacancy somebody has also logged as a leakage item. The owner sees both and a
 * combined total that is explicitly labelled as the sum of the two, so the arithmetic
 * on screen is checkable.
 *
 * The vacancy figure is 0 with no `operations` plan (no apartments exist to be
 * vacant), which is why the subtitle names what the total covers rather than
 * asserting a number the owner cannot break down.
 */
export function PortfolioLeakageCard({
  portfolio,
  canOpenLeakage,
}: {
  portfolio: DashboardPortfolio;
  canOpenLeakage: boolean;
}) {
  const { leakage, vacancy } = portfolio;
  const combined = leakage.monthlyImpact + vacancy.monthlyLoss;

  return (
    <Card>
      <CardContent className="pt-6">
        <SectionHeader
          title="Revenue leakage"
          subtitle={
            combined > 0
              ? 'Monthly revenue not being captured'
              : 'Nothing leaking right now'
          }
          actions={
            canOpenLeakage ? (
              <DashboardCardAction
                to="/financial/leakage"
                label="View"
                ariaLabel="View the revenue leakage log"
              />
            ) : undefined
          }
        />
        <div>
          <PortfolioMetricRow
            label="Vacant units"
            detail={
              vacancy.units > 0
                ? `${vacancy.units} unit${vacancy.units === 1 ? '' : 's'} available to show`
                : 'No units sitting empty'
            }
            value={`${formatUsd(vacancy.monthlyLoss)}/mo`}
            tone={vacancy.monthlyLoss > 0 ? 'negative' : 'positive'}
          />
          <PortfolioMetricRow
            label="Tracked issues"
            detail={
              leakage.count > 0
                ? `${leakage.count} unresolved item${leakage.count === 1 ? '' : 's'}`
                : 'No open leakage items'
            }
            value={`${formatUsd(leakage.monthlyImpact)}/mo`}
            tone={leakage.monthlyImpact > 0 ? 'negative' : 'positive'}
          />
          <PortfolioMetricRow
            label="Combined monthly impact"
            value={`${formatUsd(combined)}/mo`}
            tone={combined > 0 ? 'negative' : 'positive'}
            last
          />
        </div>
      </CardContent>
    </Card>
  );
}
