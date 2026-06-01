import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import { IntelligenceKpiTile } from '../components/IntelligenceKpiTile';
import { LeaderboardTable } from '../components/LeaderboardTable';
import { RANGES } from '../constants/intelligenceConstants';
import { useIntelligence } from '../hooks/useIntelligence';
import { setIntelligenceRange } from '../store/intelligenceSlice';

export function IntelligencePage() {
  const dispatch = useAppDispatch();
  const range = useAppSelector((s) => s.intelligence.range);
  const { kpis, leaderboard } = useIntelligence();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Revenue intelligence</h1>
          <p className="text-sm text-muted">
            Attribution, marketing ROI, and team leaderboard.
          </p>
        </div>
        <div className="flex gap-1.5">
          {RANGES.map((r) => (
            <button
              key={r.value}
              type="button"
              onClick={() => dispatch(setIntelligenceRange(r.value))}
              className={cn(
                'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
                range === r.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
              )}
            >
              {r.label}
            </button>
          ))}
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {kpis.map((k) => (
          <IntelligenceKpiTile key={k.id} kpi={k} />
        ))}
      </div>

      <LeaderboardTable rows={leaderboard} />
    </div>
  );
}
