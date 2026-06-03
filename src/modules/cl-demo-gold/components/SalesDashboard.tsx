import { Card, DemoButton, StatGrid, StatTile } from '@/shared/cl-demo';
import { useGoldDemo } from '../hooks/useGoldDemo';
import { activeLeadCount, hotLeadCount, hotLeads } from '../utils/goldFormat';

// Reproduces rSalesDash() for the marketer role: a three-stat strip and the
// "My Hot Leads" list.
export function SalesDashboard() {
  const { leads, actions } = useGoldDemo();

  return (
    <>
      <StatGrid>
        <StatTile label="Active Leads" value={activeLeadCount(leads)} />
        <StatTile label="Hot Leads" value={hotLeadCount(leads)} valueClassName="text-[#f87171]" />
        <StatTile label="Tours Sched." value={2} />
      </StatGrid>

      <Card
        title="My Hot Leads"
        action={<DemoButton sm onClick={() => actions.setTab('leads')}>All Leads</DemoButton>}
      >
        {hotLeads(leads).map((l) => (
          <div key={l.id} className="flex items-center justify-between border-b border-white/[0.04] py-2">
            <div>
              <div className="text-[13px] font-bold text-[#f4f8ff]">{l.name}</div>
              <div className="text-[10px] text-[#4b6278]">{l.care} • {l.status}</div>
            </div>
            <DemoButton sm onClick={() => actions.cycleLeadStatus(l.id)}>Update</DemoButton>
          </div>
        ))}
      </Card>
    </>
  );
}
