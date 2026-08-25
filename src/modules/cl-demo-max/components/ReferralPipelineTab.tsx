import { useState } from 'react';
import { Badge, Card, DemoButton, FI, StatGrid, StatTile, TBL, TD, TH } from '@/shared/cl-demo';
import { REFERRAL_STAGES, STAGE_BADGE, STAGE_COLORS } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { toneFromCls } from '../utils/maxFormat';

// Reproduces rReferrals(): paid-referral KPIs, a clickable pipeline-by-stage
// strip, and a filterable referrals table.
export function ReferralPipelineTab() {
  const { paidReferrals, actions } = useMaxDemo();
  const [typeF, setTypeF] = useState('');
  const [stageF, setStageF] = useState('');

  const list = paidReferrals.filter((r) => (!typeF || r.type === typeF) && (!stageF || r.stage === stageF));
  const paidTotal = paidReferrals.filter((r) => r.feeStatus === 'Paid').reduce((s, r) => s + r.fee, 0);
  const pending = paidReferrals.filter((r) => r.feeStatus === 'Pending').reduce((s, r) => s + r.fee, 0);
  const movedIn = paidReferrals.filter((r) => r.stage === 'Moved In').length;

  const addReferral = () => {
    const name = window.prompt('Prospect name:');
    if (!name) return;
    const source = window.prompt('Referral source:', 'A Place for Mom') || 'Unknown';
    const type = (window.prompt('Type (Paid / Organic):', 'Paid') || 'Organic') as 'Paid' | 'Organic';
    const fee = parseInt(window.prompt('Referral fee ($, 0 if none):', type === 'Paid' ? '2000' : '0') || '0') || 0;
    const care = window.prompt('Care level:', 'Assisted Living') || 'Assisted Living';
    actions.addPaidReferral({ name, source, type, fee, care });
  };

  return (
    <>
      <StatGrid>
        <StatTile label="Total Referrals" value={paidReferrals.length} sub="All sources" />
        <StatTile label="Paid Referrals" value={paidReferrals.filter((r) => r.type === 'Paid').length} valueClassName="text-[#f59e0b]" sub="APFM, Caring, SA" />
        <StatTile label="Fees Paid" value={`$${paidTotal.toLocaleString()}`} valueClassName="text-[#4fc87a]" sub="Confirmed move-ins" />
        <StatTile label="Pending Fees" value={`$${pending.toLocaleString()}`} valueClassName="text-[#f87171]" sub="On move-in" />
        <StatTile label="Moved In" value={movedIn} valueClassName="text-[#4fc87a]" sub="This period" />
      </StatGrid>

      <Card title="Pipeline by Stage" action={<DemoButton variant="x" sm onClick={() => { setTypeF(''); setStageF(''); }}>Reset Filter</DemoButton>}>
        <div className="flex flex-wrap gap-2">
          {REFERRAL_STAGES.map((stage) => {
            const col = STAGE_COLORS[stage] || '#8ba4c4';
            const cnt = paidReferrals.filter((r) => r.stage === stage).length;
            return (
              <div key={stage} role="button" onClick={() => setStageF(stage)} className="min-w-[80px] cursor-pointer rounded-[10px] bg-[#071120] px-[14px] py-2.5 text-center" style={{ border: `1px solid ${col}33` }}>
                <div className="text-[18px] font-black" style={{ color: col }}>{cnt}</div>
                <div className="mt-0.5 text-[10px] text-[#6b7fa3]">{stage}</div>
              </div>
            );
          })}
        </div>
      </Card>

      <Card
        title={
          <div className="flex flex-wrap gap-2">
            <select autoComplete="off" className={`${FI} w-[150px]`} value={typeF} onChange={(e) => setTypeF(e.target.value)}><option value="">All Types</option><option value="Paid">Paid</option><option value="Organic">Organic</option></select>
            <select autoComplete="off" className={`${FI} w-[180px]`} value={stageF} onChange={(e) => setStageF(e.target.value)}><option value="">All Stages</option>{REFERRAL_STAGES.map((s) => <option key={s}>{s}</option>)}</select>
          </div>
        }
        action={<DemoButton sm onClick={addReferral}>+ Add Referral</DemoButton>}
      >
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>{['Prospect', 'Stage', 'Source', 'Type', 'Fee', 'Fee Status', 'Care', 'Assigned', 'Tour Date', 'Actions'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {list.length === 0 ? (
                <tr><td colSpan={10} className="px-2.5 py-5 text-center text-[#4b6278]">No referrals match filter.</td></tr>
              ) : (
                list.map((r) => (
                  <tr key={r.id} className="hover:bg-white/[0.02]">
                    <td className={TD}><div className="font-bold text-[#f4f8ff]">{r.name}</div><div className="text-[10px] text-[#4b6278]">{r.source}</div></td>
                    <td className={TD}><Badge tone={toneFromCls(STAGE_BADGE[r.stage] || 'bx')}>{r.stage}</Badge></td>
                    <td className={TD}>{r.partner}</td>
                    <td className={TD}><Badge tone={r.type === 'Paid' ? 'amber' : 'blue'}>{r.type}</Badge></td>
                    <td className={TD}>{r.fee ? `$${r.fee.toLocaleString()}` : '—'}</td>
                    <td className={TD}><Badge tone={r.feeStatus === 'Paid' ? 'green' : r.feeStatus === 'Pending' ? 'amber' : 'neutral'}>{r.feeStatus || 'N/A'}</Badge></td>
                    <td className={TD}>{r.care}</td>
                    <td className={TD}>{r.assigned}</td>
                    <td className={TD}>{r.tourDate || '—'}</td>
                    <td className={`${TD} whitespace-nowrap`}><div className="flex gap-1"><DemoButton sm onClick={() => actions.advancePaidReferral(r.id)}>Advance</DemoButton><DemoButton variant="x" sm onClick={() => actions.viewRef(r.id)}>Detail</DemoButton></div></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}
