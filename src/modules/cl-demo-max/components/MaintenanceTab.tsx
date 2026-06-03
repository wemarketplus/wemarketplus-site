import { Card, DemoButton, StatGrid, StatTile } from '@/shared/cl-demo';
import { MaintenanceTable } from './MaintenanceTable';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { countMaint } from '../utils/maxFormat';

// Reproduces rMaintenance(): three-stat strip + work-orders card.
export function MaintenanceTab() {
  const { maintTickets, actions } = useMaxDemo();
  return (
    <>
      <StatGrid>
        <StatTile label="Open" value={countMaint(maintTickets, 'open')} valueClassName="text-[#f87171]" />
        <StatTile label="In Progress" value={countMaint(maintTickets, 'in_progress')} valueClassName="text-[#f59e0b]" />
        <StatTile label="Completed" value={countMaint(maintTickets, 'completed')} valueClassName="text-[#4fc87a]" />
      </StatGrid>
      <Card title="Work Orders" action={<DemoButton sm onClick={() => actions.openModal('addTicket')}>+ New Ticket</DemoButton>}>
        <MaintenanceTable />
      </Card>
    </>
  );
}
