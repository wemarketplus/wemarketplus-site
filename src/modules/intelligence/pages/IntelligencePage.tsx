import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useAppDispatch } from '@/app/hooks';
import { Alert, SectionHeader } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import { IntelligenceKpiTile } from '../components/IntelligenceKpiTile';
import { LeaderboardTable } from '../components/LeaderboardTable';
import { MarketingRoiTable } from '../components/MarketingRoiTable';
import {
  IntakeByOriginTable,
  ReferralFunnelTable,
} from '../components/ReferralFunnelTable';
import { RevenueBySourceTable } from '../components/RevenueBySourceTable';
import { RevenueOutlookPanel } from '../components/RevenueOutlookPanel';
import { RANGES } from '../constants/intelligenceConstants';
import { useIntelligence } from '../hooks/useIntelligence';
import { setIntelligenceRange } from '../store/intelligenceSlice';
import { formatCount, formatLostReason } from '../utils/intelligenceUtils';

/**
 * The Intelligence group: Revenue Intelligence, Marketing ROI and the Leaderboard on
 * one screen, over one window.
 *
 * Every figure comes from /intelligence/*. This screen previously rendered invented
 * KPIs and three fictional marketers with no data layer behind it — which is worse
 * than an outage, because the numbers looked plausible. If the API cannot answer,
 * this page now says so instead of showing anything.
 */
export function IntelligencePage() {
  const dispatch = useAppDispatch();
  const {
    range,
    kpis,
    revenue,
    roi,
    leaderboard,
    analytics,
    isLoading,
    error,
    isEmpty,
  } = useIntelligence();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>
            Revenue intelligence
          </h1>
          <p className="text-sm text-muted">
            Attribution, marketing ROI, and team leaderboard.
          </p>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => dispatch(setIntelligenceRange(r.value))}
              className={cn(
                'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
                range === r.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
              )}
            >
              {r.label}
            </button>
          ))}
        </div>
      </header>

      {error && (
        <Alert tone="r">
          <strong className="font-bold">Intelligence could not be loaded.</strong>{' '}
          The reporting endpoints did not answer, so no figures are shown. Nothing on
          this screen is estimated — retry, or check that your plan includes the
          Intelligence group.
        </Alert>
      )}

      {isLoading && !revenue && (
        <p className="text-sm text-muted">Loading attributed revenue…</p>
      )}

      {isEmpty && (
        <Alert tone="b">
          <strong className="font-bold">
            No revenue attributed in this window.
          </strong>{' '}
          Invoices carry a referral source only when one is set on them. Raise an
          invoice against an admitted pipeline to see it credited to the account that
          produced it.
        </Alert>
      )}

      {kpis.length > 0 && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {kpis.map((k) => (
            <IntelligenceKpiTile key={k.id} kpi={k} />
          ))}
        </div>
      )}

      {/*
        Cost per admission and the forecast. Rendered above the per-source table
        because they answer the two questions a director asks before "which
        facility" — what did this cost, and what is coming.
      */}
      {revenue && <RevenueOutlookPanel outlook={revenue.outlook} />}

      {revenue && revenue.bySource.length > 0 && (
        <section className="space-y-3">
          <SectionHeader
            title="Revenue by referral source"
            subtitle="Which facilities produced the money. Billed, collected and outstanding are attributed through the invoice's referral source."
          />
          <RevenueBySourceTable rows={revenue.bySource} />
        </section>
      )}

      {revenue && revenue.unattributedInvoiced > 0 && (
        <Alert tone="y">
          <strong className="font-bold">Some revenue is not attributed.</strong>{' '}
          Invoices without a referral source are counted in the totals but cannot be
          credited to an account, so per-source figures understate reality. Set the
          referral source on those invoices to close the gap.
        </Alert>
      )}

      {roi && roi.bySource.length > 0 && (
        <section className="space-y-3">
          <SectionHeader
            title="Marketing ROI"
            subtitle="Return per unit of logged effort — notes, completed visits and completed jobs. The product tracks no marketing spend, so this is deliberately not a currency-denominated ROI."
          />
          <MarketingRoiTable rows={roi.bySource} />
        </section>
      )}

      <section className="space-y-3">
        <SectionHeader
          title="Leaderboard"
          subtitle="Ranked by admissions, then attributed revenue. A rep with no goals set shows no goal pace rather than 0%."
        />
        <LeaderboardTable rows={leaderboard} />
      </section>

      {analytics && analytics.funnel.length > 0 && (
        <section className="space-y-3">
          <SectionHeader
            title="Referral funnel"
            subtitle="Leads through to admissions and revenue, per account."
          />
          <ReferralFunnelTable rows={analytics.funnel} />
        </section>
      )}

      {analytics && analytics.intakeByOrigin.length > 0 && (
        <section className="space-y-3">
          <SectionHeader
            title="Intake by origin"
            subtitle="How referrals arrived — fax, web form, phone, email, walk-in or spreadsheet import."
          />
          <IntakeByOriginTable rows={analytics.intakeByOrigin} />
        </section>
      )}

      {analytics && analytics.lostReasons.length > 0 && (
        <section className="space-y-3">
          <SectionHeader
            title="Why pipelines were lost"
            subtitle="Captured on every move into lost, so re-engagement can be targeted by reason."
          />
          <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {analytics.lostReasons.map((row) => (
              <li
                key={row.lostReason}
                className="flex items-center justify-between rounded-lg border border-border/[0.08] px-4 py-3 text-sm"
              >
                <span className="text-foreground">
                  {formatLostReason(row.lostReason)}
                </span>
                <span className="font-bold text-foreground">
                  {formatCount(row.count)}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
