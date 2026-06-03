import { Card, DemoButton } from '@/shared/cl-demo';
import { HousekeepingTable } from './HousekeepingTable';
import { useGoldDemo } from '../hooks/useGoldDemo';

// Reproduces rHousekeeping(): the housekeeping task board card.
export function HousekeepingTab() {
  const { actions } = useGoldDemo();

  return (
    <Card
      title="Housekeeping Task Board"
      action={<DemoButton sm onClick={actions.promptAddHk}>+ Assign Task</DemoButton>}
    >
      <HousekeepingTable />
    </Card>
  );
}
