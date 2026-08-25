import { PAGE_TITLE, SECTION_TITLE } from '@/shared/ui/core/typography';
import { Trophy } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill, StatTile } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import { useGetMyPerformanceQuery } from '../api/intelligenceApi';

const asPercent = (rate: number | null): string =>
  rate === null ? '—' : `${Math.round(rate * 100)}%`;

/**
 * How this marketer ranks against their team — admits, conversion and visits.
 *
 * Reads `/intelligence/my-performance`, which is a deliberately NARROWER
 * projection than the admin Leaderboard: no revenue, no email, no role. Per-rep
 * revenue is a management report, and widening the admin route's role gate
 * would have leaked all three to every field user.
 */
export function MarketerLeaderboardPage() {
  const { data, isLoading, isError } = useGetMyPerformanceQuery();

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Leaderboard</h1>
        <p className="text-sm text-muted">
          How you rank against your team on admits, conversion and visits.
        </p>
      </header>

      {isError ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            We could not load the leaderboard right now.
          </CardContent>
        </Card>
      ) : isLoading || !data ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading standings…
          </CardContent>
        </Card>
      ) : (
        <>
          {data.me === null ? (
            // Distinct from a row of zeroes: a rep with no activity in the
            // window has not scored nothing, they simply are not ranked yet.
            <Card>
              <CardContent className="px-6 py-6 text-sm text-muted-soft">
                You have no logged activity in this window yet, so you are not
                ranked. Log a visit or a call and you will appear here.
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatTile
                label="Your rank"
                value={`#${data.me.rank}`}
                hint={`of ${data.standings.length}`}
                tone="gd"
                icon={Trophy}
              />
              <StatTile
                label="Admissions"
                value={String(data.me.admits)}
                tone="g"
              />
              <StatTile
                label="Conversion"
                value={asPercent(data.me.conversionRate)}
                hint="Of your closed referrals"
                tone="b"
              />
              <StatTile
                label="Visits"
                value={String(data.me.appointmentsCompleted)}
                tone="y"
              />
            </div>
          )}

          <Card>
            <CardContent className="px-0 py-0">
              <header className="px-6 py-4">
                <h2 className={SECTION_TITLE}>
                  Team standings
                </h2>
                <p className="text-[11px] text-muted-soft">
                  Last 90 days · ranked by admissions
                </p>
              </header>
              <div className="overflow-x-auto border-t border-border">
                <table className="w-full min-w-[34rem] border-collapse text-sm">
                  <thead>
                    <tr className="bg-surface-elevated">
                      {['', 'Rep', 'Admits', 'Conversion', 'Visits', 'Touches'].map(
                        (h, i) => (
                          <th
                            key={h || i}
                            className={cn(
                              'px-4 py-2.5 text-[10px] font-semibold uppercase tracking-label text-muted-soft',
                              i <= 1 ? 'text-left' : 'text-right',
                            )}
                          >
                            {h}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {data.standings.map((row) => (
                      <tr
                        key={row.userId}
                        className={cn(
                          'border-t border-border',
                          row.isMe && 'bg-primary/[0.05]',
                        )}
                      >
                        <td className="px-4 py-2.5 tabular-nums text-muted-soft">
                          {row.rank}
                        </td>
                        <td
                          className={cn(
                            'px-4 py-2.5 text-foreground',
                            row.isMe && 'font-semibold',
                          )}
                        >
                          {row.name}
                          {row.isMe && (
                            <Pill tone="b" className="ml-2">
                              You
                            </Pill>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-right tabular-nums text-foreground">
                          {row.admits}
                        </td>
                        <td className="px-4 py-2.5 text-right tabular-nums text-muted">
                          {asPercent(row.conversionRate)}
                        </td>
                        <td className="px-4 py-2.5 text-right tabular-nums text-muted">
                          {row.appointmentsCompleted}
                        </td>
                        <td className="px-4 py-2.5 text-right tabular-nums text-muted">
                          {row.touches}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {/* Says what the number means. A conversion rate with no stated
                  denominator is the kind of figure people argue about later. */}
              <p className="px-6 py-3 text-[11px] text-muted-soft">
                Conversion is the share of each rep's <em>closed</em> referrals
                that were admitted. Open referrals are not counted against it.
              </p>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
