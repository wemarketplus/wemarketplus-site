import { Card, DemoButton, StatGrid, StatTile } from '@/shared/cl-demo';
import { APT_STATUS_COLORS, APT_STATUS_LABELS, UNIT_STATUS_ORDER } from '../constants/maxStatus';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { countAptStatus, hotLeadCount, occupancyRate, openMaintCount } from '../utils/maxFormat';

// Reproduces rDash() for director/admin: six-stat strip + Unit Status and
// Operations Alerts cards.
export function ExecutiveDashboard() {
  const { apts, leads, maintTickets, actions } = useMaxDemo();
  const rate = occupancyRate(apts);
  const occ = countAptStatus(apts, 'occupied');
  const avail = countAptStatus(apts, 'available');
  const mr = countAptStatus(apts, 'make_ready');
  const notice = countAptStatus(apts, 'on_notice');

  return (
    <>
      <StatGrid>
        <StatTile label="Occupancy" value={`${rate}%`} sub={`${occ} of ${apts.length} units`} subClassName="text-[#4fc87a]" onClick={() => actions.setTab('occupancy')} />
        <StatTile label="Available Units" value={avail} valueClassName="text-[#4fc87a]" sub="Ready to show" onClick={() => actions.setTab('apartments')} />
        <StatTile label="Make-Ready" value={mr} valueClassName="text-[#f59e0b]" sub="In progress" subClassName="text-[#f87171]" onClick={() => actions.setTab('makeready')} />
        <StatTile label="On-Notice" value={notice} valueClassName="text-[#f87171]" sub="Moving out soon" subClassName="text-[#f59e0b]" onClick={() => actions.setTab('apartments')} />
        <StatTile label="Hot Leads" value={hotLeadCount(leads)} valueClassName="text-[#f87171]" sub="Need attention" onClick={() => actions.setTab('leads')} />
        <StatTile label="Open Work Orders" value={openMaintCount(maintTickets)} valueClassName="text-[#f87171]" sub="Require attention" subClassName="text-[#f87171]" onClick={() => actions.setTab('maintenance')} />
      </StatGrid>

      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <Card title="Unit Status" action={<DemoButton sm onClick={() => actions.setTab('apartments')}>View All</DemoButton>}>
          {UNIT_STATUS_ORDER.map((status) => {
            const color = APT_STATUS_COLORS[status];
            return (
              <div key={status} className="mb-2.5 flex items-center gap-2.5">
                <div className="h-2.5 w-2.5 flex-shrink-0 rounded-full" style={{ background: color }} />
                <div className="flex-1 text-[13px] text-[#c8d6e8]">{APT_STATUS_LABELS[status]}</div>
                <div className="text-[20px] font-black" style={{ color }}>{countAptStatus(apts, status)}</div>
              </div>
            );
          })}
        </Card>

        <Card title="Operations Alerts">
          <div className="flex flex-col gap-2">
            <div className="rounded-[8px] border border-[#f87171]/15 bg-[#f87171]/[0.06] px-3 py-2.5">
              <div className="text-[12px] font-bold text-[#f87171]">Unit 104 On-Notice</div>
              <div className="mt-0.5 text-[11px] text-[#6b7fa3]">Earl Davis moving out Feb 28. <DemoButton sm onClick={() => actions.scheduleMakeReady(4)}>Schedule Make-Ready</DemoButton></div>
            </div>
            <div className="rounded-[8px] border border-[#f59e0b]/15 bg-[#f59e0b]/[0.06] px-3 py-2.5">
              <div className="text-[12px] font-bold text-[#f59e0b]">2 Units In Make-Ready</div>
              <div className="mt-0.5 text-[11px] text-[#6b7fa3]">Units 103 and 108 — est. ready Feb 14-15. <DemoButton variant="x" sm onClick={() => actions.setTab('makeready')}>View Board</DemoButton></div>
            </div>
            <div className="rounded-[8px] border border-[#4fc87a]/15 bg-[#4fc87a]/[0.06] px-3 py-2.5">
              <div className="text-[12px] font-bold text-[#4fc87a]">2 Hot Leads</div>
              <div className="mt-0.5 text-[11px] text-[#6b7fa3]">Dorothy Harrison and Gloria Tran need action today. <DemoButton variant="g" sm onClick={() => actions.setTab('leads')}>View Leads</DemoButton></div>
            </div>
          </div>
        </Card>
      </div>
    </>
  );
}
