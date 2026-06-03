import { Badge, Card, DemoButton, StatGrid, StatTile, TBL, TD, TH } from '@/shared/cl-demo';
import { PR_PIPELINE_STAGES, PR_STAGE_BADGE, PR_STAGE_COLORS } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { toneFromCls } from '../utils/maxFormat';

// Reproduces rPaidRefs(): the paid referral portal — KPIs, pipeline strip, and
// the referral table with advance / detail actions.
export function PaidRefsTab() {
  const { paidRefsPortal, actions } = useMaxDemo();
  const hot = paidRefsPortal.filter((r) => r.urgency === 'hot').length;
  const pendFees = paidRefsPortal.filter((r) => r.fee_status === 'pending').reduce((s, r) => s + r.referral_fee, 0);
  const paidFees = paidRefsPortal.filter((r) => r.fee_status === 'paid').reduce((s, r) => s + r.referral_fee, 0);
  const movedIn = paidRefsPortal.filter((r) => r.stage === 'Moved In').length;

  const addRef = () => {
    const name = window.prompt('Prospect name:');
    if (!name) return;
    const src = window.prompt('Referral source:', 'A Place for Mom') || 'Other';
    const fee = parseFloat(window.prompt('Referral fee ($):', '2000') || '0') || 0;
    actions.addPaidRefPortal({ prospect_name: name, source_name: src, referral_fee: fee });
  };

  return (
    <>
      <StatGrid>
        <StatTile label="Total Paid Referrals" value={paidRefsPortal.length} sub="All sources" />
        <StatTile label="Hot Urgency" value={hot} valueClassName="text-[#f87171]" sub="Contact immediately" />
        <StatTile label="Pending Fees" value={`$${pendFees.toLocaleString()}`} valueClassName="text-[#f59e0b]" sub="On move-in" />
        <StatTile label="Fees Collected" value={`$${paidFees.toLocaleString()}`} valueClassName="text-[#4fc87a]" sub="Confirmed" />
        <StatTile label="Moved In" value={movedIn} valueClassName="text-[#4fc87a]" sub="Converted" />
      </StatGrid>

      <Card title="Paid Referral Pipeline" action={<DemoButton sm onClick={addRef}>+ Add Paid Referral</DemoButton>}>
        <div className="mb-3 flex flex-wrap gap-2">
          {PR_PIPELINE_STAGES.map((stage) => {
            const col = PR_STAGE_COLORS[stage] || '#8ba4c4';
            const cnt = paidRefsPortal.filter((r) => r.stage === stage).length;
            return (
              <div key={stage} className="min-w-[80px] rounded-[10px] bg-[#071120] px-3 py-2 text-center" style={{ border: `1px solid ${col}33` }}>
                <div className="text-[16px] font-black" style={{ color: col }}>{cnt}</div>
                <div className="mt-0.5 text-[9px] text-[#6b7fa3]">{stage}</div>
              </div>
            );
          })}
        </div>
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>{['Prospect', 'Source', 'Care', 'Stage', 'Urgency', 'Fee', 'Status', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {paidRefsPortal.map((r) => (
                <tr key={r.id} className="hover:bg-white/[0.02]">
                  <td className={TD}><div className="font-bold text-[#f4f8ff]">{r.prospect_name}</div><div className="text-[10px] text-[#4b6278]">{r.prospect_phone}</div></td>
                  <td className={TD}><div className="font-semibold">{r.source_name}</div><div className="text-[10px] text-[#4b6278]">{r.source_contact}</div></td>
                  <td className={TD}>{r.care_level || '—'}</td>
                  <td className={TD}><Badge tone={toneFromCls(PR_STAGE_BADGE[r.stage] || 'bx')}>{r.stage}</Badge></td>
                  <td className={TD}>{r.urgency ? <Badge tone={r.urgency === 'hot' ? 'red' : r.urgency === 'warm' ? 'amber' : 'blue'}>{r.urgency.toUpperCase()}</Badge> : '—'}</td>
                  <td className={TD}>{r.referral_fee ? `$${r.referral_fee.toLocaleString()}` : '—'}</td>
                  <td className={TD}><Badge tone={r.fee_status === 'paid' ? 'green' : r.fee_status === 'pending' ? 'amber' : 'neutral'}>{r.fee_status || 'pending'}</Badge></td>
                  <td className={`${TD} whitespace-nowrap`}><div className="flex gap-1"><DemoButton sm onClick={() => actions.advancePaidRefPortal(r.id)}>Advance</DemoButton><DemoButton variant="x" sm onClick={() => actions.viewPaidRefPortal(r.id)}>Detail</DemoButton></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
