import { StatGrid, StatTile } from '@/shared/cl-demo';
import { MaintenanceTable } from './MaintenanceTable';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { countMaint } from '../utils/goldFormat';

// Reproduces rMaintDash() for the maintenance role: a three-stat strip plus the
// bare work-orders table (no card wrapper, matching the reference).
export function MaintenanceDashboard() {
  const { maintTickets } = useGoldDemo();

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
