import { useOperations } from '../hooks/useOperations';
import { useOperationsView } from '../hooks/useOperationsView';
import { ApartmentsTable } from '../components/ApartmentsTable';
import { MakeReadyBoard } from '../components/MakeReadyBoard';
import { OccupancyHero } from '../components/OccupancyHero';
import { OperationsViewNav } from '../components/OperationsViewNav';
import { ServiceTicketsTable } from '../components/ServiceTicketsTable';

export function ClOperationsPage() {
  const { view, changeView } = useOperationsView();
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

      <OperationsViewNav view={view} onViewChange={changeView} />

      {view === 'inventory' && <ApartmentsTable apartments={apartments} />}
      {view === 'make-ready' && <MakeReadyBoard tickets={makeReady} />}
      {view === 'maintenance' && <ServiceTicketsTable tickets={maintenance} />}
      {view === 'housekeeping' && <ServiceTicketsTable tickets={housekeeping} />}
    </div>
  );
}
