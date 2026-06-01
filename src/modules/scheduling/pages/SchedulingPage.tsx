import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import { TerritoryTable } from '../components/TerritoryTable';
import { TerritoryHeatmap } from '../components/TerritoryHeatmap';
import { useTerritories } from '../hooks/useTerritories';
import { setSchedulingView } from '../store/schedulingSlice';
import type { SchedulingUiState } from '../types/schedulingTypes';

const VIEWS: ReadonlyArray<{ value: SchedulingUiState['view']; label: string }> = [
  { value: 'territories', label: 'Territory table' },
  { value: 'heatmap', label: 'Heat map' },
];

export function SchedulingPage() {
  const dispatch = useAppDispatch();
  const view = useAppSelector((s) => s.scheduling.view);
  const { territories } = useTerritories();

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Territories</h1>
          <p className="text-sm text-muted">
            Marketer coverage across your service area.
          </p>
        </div>
        <div className="flex gap-1.5">
          {VIEWS.map((v) => (
            <button
              key={v.value}
              type="button"
              onClick={() => dispatch(setSchedulingView(v.value))}
              className={cn(
                'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
                view === v.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
              )}
            >
              {v.label}
            </button>
          ))}
        </div>
      </header>

      {view === 'territories' && <TerritoryTable territories={territories} />}
      {view === 'heatmap' && <TerritoryHeatmap territories={territories} />}
    </div>
  );
}
