import { formatUsd } from '@/modules/cl-financial/utils/financialFormat';
import { Card, CardContent } from '@/shared/ui/core';
import { SectionHeader } from '@/shared/ui/data-display';
import type { DashboardPortfolio } from '../types/dashboardTypes';
import { DashboardCardAction } from './DashboardCardAction';
import { PortfolioMetricRow } from './PortfolioMetricRow';

/**
 * "Referral Pipeline" — step 5: "Click Full Pipeline from the Referral Pipeline card
 * to see paid vs. organic lead sources."
 *
 * PAID VS ORGANIC IS THE EXISTING PRODUCT TAXONOMY, not a new one: a referral whose
 * fee status is `na` is already rendered to the user as the word "Organic" on the
 * Paid Referral Portal, which is exactly the screen "Full Pipeline" opens. Every
 * other fee status means a fee was quoted for the introduction. Computing the split
 * any other way — for instance from the free-text `source` column — would make this
 * card disagree with the screen it links to.
 *
 * The bar is proportional to `paidPercent`, which the server rounds so the tile and
 * the portal cannot round independently and land a point apart. It is decoration
 * over the numbers, not the only way to read them, and it is hidden from the
 * accessibility tree for that reason.
 */
export function PortfolioReferralPipelineCard({
  portfolio,
}: {
  portfolio: DashboardPortfolio;
}) {
  const { referralMix, pendingReferralFees } = portfolio;
  const { paid, organic, total, paidPercent } = referralMix;

  return (
    <Card>
      <CardContent className="pt-6">
        <SectionHeader
          title="Referral pipeline"
          subtitle={
            total > 0
              ? `${total} referral${total === 1 ? '' : 's'} received`
              : 'No referrals received yet'
          }
          actions={
            <DashboardCardAction
              to="/paid-referrals"
              label="Full Pipeline"
              ariaLabel="Open the full referral pipeline"
            />
          }
        />

        {total > 0 && (
          <div
            aria-hidden="true"
            className="mb-3 flex h-2 overflow-hidden rounded-pill bg-surface-raised"
          >
            <div
              className="h-full bg-[#92570b]/70"
              style={{ width: `${paidPercent}%` }}
            />
            <div className="h-full flex-1 bg-[#0f5c8a]/60" />
          </div>
        )}

        <div>
          <PortfolioMetricRow
            label="Paid sources"
            detail={total > 0 ? `${paidPercent}% of referrals` : undefined}
            value={String(paid)}
            tone="caution"
          />
          <PortfolioMetricRow
            label="Organic sources"
            detail={total > 0 ? `${100 - paidPercent}% of referrals` : undefined}
            value={String(organic)}
            tone="info"
          />
          <PortfolioMetricRow
            label="Fees pending"
            detail={
              pendingReferralFees.count > 0
                ? `across ${pendingReferralFees.count} referral${pendingReferralFees.count === 1 ? '' : 's'}`
                : undefined
            }
            value={formatUsd(pendingReferralFees.total)}
            tone={pendingReferralFees.total > 0 ? 'caution' : 'positive'}
            last
          />
        </div>
      </CardContent>
    </Card>
  );
}
