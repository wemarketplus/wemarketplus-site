import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { Alert, SectionHeader, StatTile } from '@/shared/ui/data-display';
import { useGetWeeklyReportQuery } from '../api/intelligenceApi';
import { LeaderboardTable } from '../components/LeaderboardTable';
import { RevenueBySourceTable } from '../components/RevenueBySourceTable';
import {
  formatCount,
  formatLostReason,
  formatMoney,
  formatRate,
} from '../utils/intelligenceUtils';

/**
 * The Weekly Report — the Executive Director touchpoint the module-flow document could
 * not find in the module inventory and suspected was "a scheduled email job with no nav
 * entry". There was no such job. This is it, as a screen rather than an email, because an
 * email cannot be tier-gated, role-gated or audited the way the rest of the Intelligence
 * group is.
 *
 * Every figure comes from the same aggregates the Revenue Intelligence screen uses, so
 * the two can never disagree.
 */
export function WeeklyReportPage() {
  const { data, isLoading, error } = useGetWeeklyReportQuery();

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Weekly report</h1>
        <p className="text-sm text-muted">
          The last seven days: what came in, what closed, and who moved it.
          {data ? ` ${data.window.from.slice(0, 10)} → ${data.window.to.slice(0, 10)}` : ''}
        </p>
      </header>

      {error && (
        <Alert tone="r">
          <strong className="font-bold">Weekly report unavailable.</strong> The
          reporting endpoint did not answer. Nothing here is estimated.
        </Alert>
      )}

      {isLoading && <p className="text-sm text-muted">Building this week…</p>}

      {data && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Referrals received"
              value={formatCount(data.leadsReceived)}
              hint={`${formatCount(data.leadsConverted)} converted · ${formatRate(
                data.leadsReceived > 0
                  ? data.leadsConverted / data.leadsReceived
                  : null,
              )}`}
            />
            <StatTile
              label="Admissions"
              value={formatCount(data.admits)}
              hint={`${formatCount(data.lost)} lost`}
              tone={data.admits > 0 ? 'g' : undefined}
            />
            <StatTile
              label="Billed"
              value={formatMoney(data.revenueBilled)}
              hint={`${formatMoney(data.revenueCollected)} collected`}
            />
            <StatTile
              label="Visits completed"
              value={formatCount(data.visitsCompleted)}
            />
          </div>

          {data.topSources.length > 0 && (
            <section className="space-y-3">
              <SectionHeader
                title="Top referral sources this week"
                subtitle="Ranked by revenue actually attributed to the account."
              />
              <RevenueBySourceTable rows={data.topSources} />
            </section>
          )}

          <section className="space-y-3">
            <SectionHeader
              title="Rep standings"
              subtitle="Admissions first, then attributed revenue."
            />
            <LeaderboardTable rows={data.leaderboard} />
          </section>

          {data.lostReasons.length > 0 && (
            <section className="space-y-3">
              <SectionHeader
                title="Lost this week"
                subtitle="The re-engagement list, grouped by why."
              />
              <ul className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {data.lostReasons.map((row) => (
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
        </>
      )}
    </div>
  );
}
