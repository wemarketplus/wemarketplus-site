import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { cn } from '@/shared/utils/cn';
import { OPERATIONS_VIEWS } from '../constants/clOperationsConstants';
import { useOperations } from '../hooks/useOperations';
import { setOperationsView } from '../store/clOperationsSlice';
import { OccupancyHero } from '../components/OccupancyHero';
import { ApartmentsTable } from '../components/ApartmentsTable';
import { MakeReadyBoard } from '../components/MakeReadyBoard';
import { ServiceTicketsTable } from '../components/ServiceTicketsTable';

export function ClOperationsPage() {
  const dispatch = useAppDispatch();
  const view = useAppSelector((s) => s.clOperations.view);
  const { apartments, makeReady, maintenance, housekeeping, isUsingFixture } = useOperations();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Operations</h1>
        <p className="text-sm text-muted">
          Apartment inventory, make-ready board, maintenance, and housekeeping.
          {isUsingFixture && (
            <span className="ml-2 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
              Preview data
            </span>
          )}
        </p>
      </header>

      {view === 'inventory' && <OccupancyHero apartments={apartments} />}

      <nav className="flex flex-wrap gap-1.5">
        {OPERATIONS_VIEWS.map((v) => (
          <button
            key={v.value}
            type="button"
            onClick={() => dispatch(setOperationsView(v.value))}
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
      </nav>

      {view === 'inventory' && <ApartmentsTable apartments={apartments} />}
      {view === 'make-ready' && <MakeReadyBoard tickets={makeReady} />}
      {view === 'maintenance' && <ServiceTicketsTable tickets={maintenance} />}
      {view === 'housekeeping' && <ServiceTicketsTable tickets={housekeeping} />}
    </div>
  );
}
