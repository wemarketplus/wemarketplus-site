import { useOperations } from '../hooks/useOperations';
import { useOperationsView } from '../hooks/useOperationsView';
import { ApartmentsTable } from '../components/ApartmentsTable';
import { MakeReadyBoard } from '../components/MakeReadyBoard';
import { OccupancyHero } from '../components/OccupancyHero';
import { OperationsViewNav } from '../components/OperationsViewNav';
import { ServiceTicketsTable } from '../components/ServiceTicketsTable';

export function ClOperationsPage() {
  const { view, changeView } = useOperationsView();
  const { apartments, makeReady, maintenance, housekeeping } = useOperations();

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="font-display text-3xl text-foreground">Operations</h1>
        <p className="text-sm text-muted">
          Apartment inventory, make-ready board, maintenance, and housekeeping.
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
