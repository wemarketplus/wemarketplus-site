import { Trophy } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { Pill, StatTile } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import { useGetMyPerformanceQuery } from '../api/intelligenceApi';

/**
 * The marketer's own standing, and the team's.
 *
 * Reads `/intelligence/my-performance`, which is a deliberately narrower
 * projection of the Leaderboard: it carries no revenue, no email and no role,
 * because per-rep revenue is an admin report. Widening the Leaderboard's own
 * role gate would have leaked all three to every field user.
 */
export function MyPerformancePanel() {
  const { data, isLoading, isError } = useGetMyPerformanceQuery();

  if (isError) {
    return null;
  }

  if (isLoading || !data) {
    return (
      <Card>
        <CardContent className="px-6 py-6 text-xs text-muted-soft">
          Loading your performance…
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="space-y-5 px-6 py-5">
        <header className="flex items-center gap-3">
          <span className="rounded-[10px] bg-gold/[0.12] p-2 text-gold">
            <Trophy className="h-4 w-4" />
          </span>
          <div>
            <h2 className="text-sm font-semibold text-foreground">
              Your performance
            </h2>
            <p className="text-[11px] text-muted-soft">
              Last 90 days across the team
            </p>
          </div>
        </header>

        {data.me === null ? (
          // Distinct from "zero" — a rep with no rows in the window has not
          // scored 0, they simply have not been ranked yet.
          <p className="text-xs text-muted-soft">
            You have no logged activity in this window yet.
          </p>
        ) : (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatTile label="Rank" value={`#${data.me.rank}`} tone="gd" />
            <StatTile label="Admissions" value={String(data.me.admits)} tone="g" />
            <StatTile
              label="Visits"
              value={String(data.me.appointmentsCompleted)}
              tone="b"
            />
            <StatTile label="Touches" value={String(data.me.touches)} tone="y" />
          </div>
        )}

        {data.standings.length > 1 && (
          <div>
            <p className="mb-2 text-[10px] uppercase tracking-[0.14em] text-muted-soft">
              Team standings
            </p>
            <ul className="divide-y divide-border">
              {data.standings.map((row) => (
                <li
                  key={row.userId}
                  className={cn(
                    'flex items-center gap-3 py-2',
                    row.isMe && 'font-semibold',
                  )}
                >
                  <span className="w-6 text-xs tabular-nums text-muted-soft">
                    {row.rank}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm text-foreground">
                    {row.name}
                    {row.isMe && (
                      <Pill tone="b" className="ml-2">
                        You
                      </Pill>
                    )}
                  </span>
                  <span className="text-xs tabular-nums text-muted">
                    {row.admits} admits
                  </span>
                  <span className="text-xs tabular-nums text-muted-soft">
                    {row.appointmentsCompleted} visits
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
