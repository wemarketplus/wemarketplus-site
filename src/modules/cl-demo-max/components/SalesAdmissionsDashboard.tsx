import { Card, DemoButton, StatGrid, StatTile } from '@/shared/cl-demo';
import { OPS_STATUS_ROWS } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { countAptStatus, hotLeadCount, hotLeads, occupancyRate, tourCount } from '../utils/maxFormat';

// Reproduces rSalesAdmissionsDash(): sales/admissions hero, KPI strip, hot
// leads + paid referrals, operations status + quick actions, and a lock notice.
export function SalesAdmissionsDashboard() {
  const { apts, leads, paidReferrals, actions } = useMaxDemo();
  const occ = countAptStatus(apts, 'occupied');
  const avail = countAptStatus(apts, 'available');
  const rate = occupancyRate(apts);
  const paidRefs = paidReferrals.filter((r) => r.type === 'Paid' && r.stage !== 'Moved In' && r.stage !== 'Lost').length;

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2.5 rounded-[14px] border border-[#f59e0b]/20 bg-gradient-to-br from-[#f59e0b]/[0.05] to-[#3d9ee8]/[0.03] px-[18px] py-[14px]">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.06em] text-[#f59e0b]">Sales/Admissions</div>
          <div className="text-[22px] font-black text-[#f4f8ff]">Sunrise Senior Living</div>
          <div className="text-[12px] text-[#6b7fa3]">Sales &amp; Operations View — Reports require Executive Director access</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <DemoButton sm onClick={() => actions.setTab('leads')}>Lead Pipeline</DemoButton>
          <DemoButton variant="g" sm onClick={() => actions.setTab('referrals')}>Referrals</DemoButton>
          <DemoButton variant="x" sm onClick={() => actions.setTab('tours')}>Tours</DemoButton>
        </div>
      </div>

      <StatGrid>
        <StatTile label="Hot Leads" value={hotLeadCount(leads)} valueClassName="text-[#f87171]" sub="Need attention" onClick={() => actions.setTab('leads')} />
        <StatTile label="Tours Scheduled" value={tourCount(leads)} valueClassName="text-[#f59e0b]" sub="This week" onClick={() => actions.setTab('tours')} />
        <StatTile label="Occupancy" value={`${rate}%`} valueClassName="text-[#4fc87a]" sub={`${occ}/${apts.length} units`} onClick={() => actions.setTab('occupancy')} />
        <StatTile label="Available Units" value={avail} valueClassName="text-[#4fc87a]" sub="Ready to show" onClick={() => actions.setTab('apartments')} />
        <StatTile label="Active Paid Referrals" value={paidRefs} valueClassName="text-[#f59e0b]" sub="In pipeline" onClick={() => actions.setTab('referrals')} />
      </StatGrid>

      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <div>
          <Card title="Hot Leads" action={<DemoButton sm onClick={() => actions.setTab('leads')}>All Leads</DemoButton>}>
            {hotLeads(leads).slice(0, 4).map((l) => (
              <div key={l.id} className="border-b border-white/[0.05] py-[7px]">
                <div className="flex items-center justify-between"><strong className="text-[12px] text-[#f4f8ff]">{l.name}</strong><span className="inline-block rounded-full bg-[#f87171]/10 px-2 py-0.5 text-[10px] font-bold text-[#f87171]">Hot</span></div>
                <div className="text-[10px] text-[#4b6278]">{l.care} • {l.status}</div>
              </div>
            ))}
          </Card>
          <Card title="Paid Referrals" action={<DemoButton variant="g" sm onClick={() => actions.setTab('referrals')}>View All</DemoButton>}>
            {paidReferrals.filter((r) => r.stage !== 'Moved In' && r.stage !== 'Lost').slice(0, 4).map((r) => (
              <div key={r.id} className="border-b border-white/[0.05] py-[7px]">
                <div className="flex justify-between"><strong className="text-[12px] text-[#f4f8ff]">{r.name}</strong><span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-bold ${r.type === 'Paid' ? 'bg-[#f59e0b]/10 text-[#f59e0b]' : 'bg-[#3d9ee8]/10 text-[#3d9ee8]'}`}>{r.type}</span></div>
                <div className="text-[10px] text-[#4b6278]">{r.stage} • {r.source}</div>
              </div>
            ))}
          </Card>
        </div>

        <div>
          <Card title="Operations Status" action={<DemoButton variant="x" sm onClick={() => actions.setTab('apartments')}>Units</DemoButton>}>
            {OPS_STATUS_ROWS.map(([label, key, color]) => (
              <div key={key} className="flex items-center justify-between border-b border-white/[0.04] py-1.5">
                <div className="flex items-center gap-2"><div className="h-2 w-2 rounded-full" style={{ background: color }} /><span className="text-[12px] text-[#c8d6e8]">{label}</span></div>
                <span className="text-[14px] font-extrabold" style={{ color }}>{countAptStatus(apts, key)}</span>
              </div>
            ))}
          </Card>
          <Card title="Quick Actions">
            <div className="flex flex-col gap-2">
              <DemoButton onClick={() => actions.setTab('leads')}>+ Add Lead</DemoButton>
              <DemoButton variant="g" onClick={() => actions.setTab('tours')}>Schedule Tour</DemoButton>
              <DemoButton variant="x" onClick={() => actions.setTab('notes')}>Log Activity Note</DemoButton>
              <DemoButton variant="x" onClick={() => actions.setTab('aircall')}>Open Aircall</DemoButton>
            </div>
          </Card>
        </div>
      </div>

      <div className="mt-1.5 flex items-center gap-2 rounded-[9px] border border-[#f87171]/20 bg-[#f87171]/[0.06] px-[14px] py-2.5 text-[12px] text-[#f87171]">
        <span>🔒</span> Reports and financial analytics require Executive Director or Admin access.
      </div>
    </>
  );
}
