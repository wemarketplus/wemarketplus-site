import { HotLeadsCard } from './HotLeadsCard';
import { PipelineOverview } from './PipelineOverview';
import { StatGrid } from './StatGrid';
import { StatTile } from './StatTile';
import { TasksDueCard } from './TasksDueCard';
import { useClDemo } from '../hooks/useClDemo';
import { activeLeadCount, moveInCount, reimbursable } from '../utils/clDemoFormat';

// Dashboard tab — reproduces the reference rDash(): 6 stat tiles, the Hot Leads
// + Tasks Due Today two-card row, and the Pipeline Overview strip.
export function DashboardTab() {
  const { leads, referrals, tours, mileage, tasks, actions } = useClDemo();

  const active = activeLeadCount(leads);
  const confirmedTours = tours.filter((t) => t.status === 'Confirmed').length;
  const moveins = moveInCount(leads);
  const miles = mileage.reduce((s, m) => s + m.miles, 0);
  const openTasks = tasks.filter((t) => !t.done).length;

  return (
    <>
      <StatGrid>
        <StatTile label="Active Leads" value={active} sub="In pipeline" onClick={() => actions.setTab('leads')} />
        <StatTile label="Tours Confirmed" value={confirmedTours} sub="Goal: 12/mo" subClassName="text-[#4fc87a]" onClick={() => actions.setTab('tours')} />
        <StatTile label="Move-Ins (Feb)" value={moveins} sub="Goal: 4" subClassName="text-[#8ba4c4]" />
        <StatTile label="Referral Sources" value={referrals.length} sub="Active partners" subClassName="text-[#4fc87a]" onClick={() => actions.setTab('refs')} />
        <StatTile label="Miles (MTD)" value={miles} sub={`$${reimbursable(miles, 0)} reimbursable`} onClick={() => actions.setTab('mileage')} />
        <StatTile label="Open Tasks" value={openTasks} valueClassName="text-[#f87171]" sub="Need attention" subClassName="text-[#f87171]" onClick={() => actions.setTab('tasks')} />
      </StatGrid>

      <div className="mb-[14px] grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <HotLeadsCard />
        <TasksDueCard />
      </div>

      <PipelineOverview />
    </>
  );
}
