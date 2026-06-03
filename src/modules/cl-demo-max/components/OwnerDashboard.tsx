import { Card, DemoButton, StatGrid, StatTile } from '@/shared/cl-demo';
import { OPS_STATUS_ROWS } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { countAptStatus, hotLeadCount, hotLeads, occupancyRate, openMaintCount, rentRoll } from '../utils/maxFormat';

// Reproduces rOwnerDash(): portfolio hero, KPI strip, and a three-column
// Sales / Operations / Financial overview.
export function OwnerDashboard() {
  const { apts, leads, maintTickets, paidReferrals, actions } = useMaxDemo();
  const rate = occupancyRate(apts);
  const occ = countAptStatus(apts, 'occupied');
  const avail = countAptStatus(apts, 'available');
  const openM = openMaintCount(maintTickets);
  const pendingFees = paidReferrals.filter((r) => r.feeStatus === 'Pending').reduce((s, r) => s + r.fee, 0);
  const totalRevenue = rentRoll(apts);
  const highMaint = maintTickets.filter((t) => t.priority === 'High' && t.status !== 'completed').length;

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-2.5 rounded-[14px] border border-[#4fc87a]/[0.12] bg-gradient-to-br from-[#4fc87a]/[0.04] to-[#f59e0b]/[0.02] px-[18px] py-[14px]">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.06em] text-[#4fc87a]">Portfolio Overview</div>
          <div className="text-[22px] font-black text-[#f4f8ff]">Sunrise Senior Living</div>
          <div className="text-[12px] text-[#6b7fa3]">Full System Visibility — Owner / Investor View</div>
        </div>
        <div className="flex flex-wrap gap-2">
          <DemoButton sm onClick={() => actions.setTab('reports')}>View Reports</DemoButton>
          <DemoButton variant="g" sm onClick={() => actions.setTab('referrals')}>Referral Pipeline</DemoButton>
        </div>
      </div>

      <StatGrid>
        <StatTile label="Occupancy Rate" value={`${rate}%`} sub={`${occ} / ${apts.length} units`} subClassName="text-[#4fc87a]" onClick={() => actions.setTab('occupancy')} />
        <StatTile label="Available Units" value={avail} valueClassName="text-[#4fc87a]" sub="Ready to show" onClick={() => actions.setTab('apartments')} />
        <StatTile label="Monthly Revenue" value={`$${totalRevenue.toLocaleString()}`} valueClassName="text-[#f59e0b]" sub="Occupied units rent roll" onClick={() => actions.setTab('ledger')} />
        <StatTile label="Pending Ref. Fees" value={`$${pendingFees.toLocaleString()}`} valueClassName="text-[#f87171]" sub="On move-in" onClick={() => actions.setTab('referrals')} />
        <StatTile label="Hot Leads" value={hotLeadCount(leads)} valueClassName="text-[#f87171]" sub="Need attention now" onClick={() => actions.setTab('leads')} />
        <StatTile label="Open Work Orders" value={openM} valueClassName="text-[#f87171]" sub="Maintenance tickets" onClick={() => actions.setTab('maintenance')} />
      </StatGrid>

      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-3">
        <div>
          <Card title="Sales Activity" action={<DemoButton sm onClick={() => actions.setTab('leads')}>View All</DemoButton>}>
            {hotLeads(leads).slice(0, 3).map((l) => (
              <div key={l.id} className="border-b border-white/[0.05] py-[7px]">
                <div className="flex items-center justify-between"><strong className="text-[12px] text-[#f4f8ff]">{l.name}</strong><span className="inline-block rounded-full bg-[#f87171]/10 px-2 py-0.5 text-[10px] font-bold text-[#f87171]">Hot</span></div>
                <div className="text-[10px] text-[#4b6278]">{l.care} • {l.status}</div>
              </div>
            ))}
          </Card>
          <Card title="Referral Pipeline" action={<DemoButton variant="g" sm onClick={() => actions.setTab('referrals')}>Full Pipeline</DemoButton>}>
            {paidReferrals.filter((r) => r.stage !== 'Moved In' && r.stage !== 'Lost').slice(0, 3).map((r) => (
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
          <Card title="Maintenance" action={<DemoButton variant="x" sm onClick={() => actions.setTab('maintenance')}>View</DemoButton>}>
            <div className="text-[12px] text-[#6b7fa3]">{openM} open ticket{openM !== 1 ? 's' : ''} — {highMaint} high priority</div>
          </Card>
        </div>

        <div>
          <Card title="Financial Overview" action={<DemoButton sm onClick={() => actions.setTab('ledger')}>Ledger</DemoButton>}>
            <div className="flex flex-col">
              <div className="flex justify-between border-b border-white/[0.05] py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Rent Roll</span><span className="font-extrabold text-[#4fc87a]">${totalRevenue.toLocaleString()}/mo</span></div>
              <div className="flex justify-between border-b border-white/[0.05] py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Occupancy</span><span className="font-extrabold text-[#f4f8ff]">{rate}%</span></div>
              <div className="flex justify-between border-b border-white/[0.05] py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Pending Ref Fees</span><span className="font-extrabold text-[#f87171]">${pendingFees.toLocaleString()}</span></div>
              <div className="flex justify-between py-[7px]"><span className="text-[12px] text-[#8ba4c4]">Available Units</span><span className="font-extrabold text-[#3d9ee8]">{avail} units</span></div>
            </div>
          </Card>
          <Card title="Revenue Leakage" action={<DemoButton sm onClick={() => actions.setTab('revenue')}>View</DemoButton>}>
            <div className="text-[12px] text-[#f87171]">${(avail * 3200).toLocaleString()}/mo potential from {avail} vacant units</div>
          </Card>
        </div>
      </div>
    </>
  );
}
