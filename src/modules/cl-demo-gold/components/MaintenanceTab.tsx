import { Card, DemoButton, StatGrid, StatTile } from '@/shared/cl-demo';
import { MaintenanceTable } from './MaintenanceTable';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { countMaint } from '../utils/goldFormat';

// Reproduces rMaintenance(): a three-stat strip plus the work-orders card.
export function MaintenanceTab() {
  const { maintTickets, actions } = useGoldDemo();

  return (
    <>
      <StatGrid>
        <StatTile label="Open" value={countMaint(maintTickets, 'open')} valueClassName="text-[#f87171]" />
        <StatTile label="In Progress" value={countMaint(maintTickets, 'in_progress')} valueClassName="text-[#f59e0b]" />
        <StatTile label="Completed" value={countMaint(maintTickets, 'completed')} valueClassName="text-[#4fc87a]" />
      </StatGrid>

      <Card
        title="Work Orders"
        action={<DemoButton sm onClick={actions.promptAddMaint}>+ New Ticket</DemoButton>}
      >
        <MaintenanceTable />
      </Card>
    </>
  );
}
