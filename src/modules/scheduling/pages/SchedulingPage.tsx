import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import { TerritoryTable } from '../components/TerritoryTable';
import { TerritoryHeatmap } from '../components/TerritoryHeatmap';
import { useTerritories } from '../hooks/useTerritories';
import { setSchedulingView } from '../store/schedulingSlice';
import { SCHEDULING_VIEWS } from '../constants/schedulingConstants';

export function SchedulingPage() {
  const dispatch = useAppDispatch();
  const view = useAppSelector((s) => s.scheduling.view);
  const { territories, isEmpty } = useTerritories();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>Territories</h1>
          <p className="text-sm text-muted">
            Marketer coverage across your service area.
          </p>
        </div>
        <div className="flex gap-1.5">
          {SCHEDULING_VIEWS.map((v) => (
            <button
              key={v.value}
              type="button"
              onClick={() => dispatch(setSchedulingView(v.value))}
              className={cn(
                'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
                view === v.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
              )}
            >
              {v.label}
            </button>
          ))}
        </div>
      </header>

      {isEmpty ? (
        <div className="rounded-card border border-border/[0.06] bg-surface p-10 text-center">
          <p className="text-sm font-semibold text-foreground">
            Territory performance analytics are coming soon
          </p>
          <p className="mt-1 text-sm text-muted">
            Visit, admission, and conversion metrics per territory require a
            reporting endpoint that is not yet available. Manage your territories
            under Territories in the meantime.
          </p>
        </div>
      ) : (
        <>
          {view === 'territories' && <TerritoryTable territories={territories} />}
          {view === 'heatmap' && <TerritoryHeatmap territories={territories} />}
        </>
      )}
    </div>
  );
}
