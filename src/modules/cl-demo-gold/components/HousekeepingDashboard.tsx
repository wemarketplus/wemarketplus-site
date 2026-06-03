import { Card } from '@/shared/cl-demo';
import { HousekeepingTable } from './HousekeepingTable';

// Reproduces rHKDash() for the housekeeping role: the task queue inside a card.
export function HousekeepingDashboard() {
  return (
    <Card title="My Housekeeping Queue">
      <HousekeepingTable />
    </Card>
  );
}
