import { Card } from '@/shared/cl-demo';
import { HousekeepingTable } from './HousekeepingTable';

// Reproduces rHKDash(): the housekeeping queue inside a card.
export function HousekeepingDashboard() {
  return (
    <Card title="My Housekeeping Queue">
      <HousekeepingTable />
    </Card>
  );
}
