import { StatGrid, StatTile } from '@/shared/cl-demo';
import { MaintenanceTable } from './MaintenanceTable';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { countMaint } from '../utils/maxFormat';

// Reproduces rMaintDash(): three-stat strip + bare work-orders table.
export function MaintenanceDashboard() {
  const { maintTickets } = useMaxDemo();
  return (
    <>
      <StatGrid>
        <StatTile label="Open Tickets" value={countMaint(maintTickets, 'open')} valueClassName="text-[#f87171]" />
        <StatTile label="In Progress" value={countMaint(maintTickets, 'in_progress')} valueClassName="text-[#f59e0b]" />
        <StatTile label="Completed" value={countMaint(maintTickets, 'completed')} valueClassName="text-[#4fc87a]" />
      </StatGrid>
      <MaintenanceTable />
    </>
  );
}
