import { Card, DemoButton } from '@/shared/cl-demo';
import { HousekeepingTable } from './HousekeepingTable';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rHousekeeping(): the housekeeping task board card.
export function HousekeepingTab() {
  const { actions } = useMaxDemo();
  return (
    <Card title="Housekeeping Task Board" action={<DemoButton sm onClick={() => actions.openModal('addTask')}>+ Assign Task</DemoButton>}>
      <HousekeepingTable />
    </Card>
  );
}
