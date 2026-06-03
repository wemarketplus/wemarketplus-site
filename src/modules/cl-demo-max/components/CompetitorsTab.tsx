import { useState } from 'react';
import { Badge, Card, DemoButton, Field, FI, TBL, TD, TH } from '@/shared/cl-demo';
import { RATE_COMPARE } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { occTone } from '../utils/maxFormat';

// Reproduces rCompetitors(): competitor tracker table, an inline add form, an
// AL rate comparison, and a market summary.
export function CompetitorsTab() {
  const { competitors, actions } = useMaxDemo();
  const [open, setOpen] = useState(false);
  const [f, setF] = useState({ name: '', city: '', dist: '', al: '', occ: '', notes: '' });

  const submit = () => {
    if (!f.name.trim()) { actions.toast('Name required.', true); return; }
    actions.addCompetitor({ name: f.name.trim(), city: f.city.trim(), dist: parseFloat(f.dist) || 0, il: 'N/A', al: f.al.trim() || 'N/A', mc: 'N/A', occ: f.occ.trim() || '—', notes: f.notes.trim() });
    setOpen(false); setF({ name: '', city: '', dist: '', al: '', occ: '', notes: '' });
  };

  return (
    <>
      <Card title="Competitor Tracker" action={<DemoButton sm onClick={() => setOpen(true)}>+ Add Competitor</DemoButton>}>
        {open && (
          <div className="mb-[14px] rounded-[10px] border border-[#f59e0b]/15 bg-[#071120] p-[14px]">
            <div className="mb-3 grid grid-cols-2 gap-3">
              <Field label="Community Name"><input className={FI} placeholder="Sunrise Gardens" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
              <Field label="City"><input className={FI} placeholder="Dallas" value={f.city} onChange={(e) => setF({ ...f, city: e.target.value })} /></Field>
              <Field label="Distance (mi)"><input className={FI} type="number" step={0.1} placeholder="2.4" value={f.dist} onChange={(e) => setF({ ...f, dist: e.target.value })} /></Field>
              <Field label="AL Rate"><input className={FI} placeholder="$4,200" value={f.al} onChange={(e) => setF({ ...f, al: e.target.value })} /></Field>
              <Field label="Occupancy"><input className={FI} placeholder="88%" value={f.occ} onChange={(e) => setF({ ...f, occ: e.target.value })} /></Field>
              <Field label="Notes"><input className={FI} placeholder="Promotions, strengths..." value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></Field>
            </div>
            <div className="flex gap-2"><DemoButton sm onClick={submit}>Add</DemoButton><DemoButton variant="x" sm onClick={() => setOpen(false)}>Cancel</DemoButton></div>
          </div>
        )}
        <div className="overflow-x-auto">
          <table className={TBL}>
            <thead>
              <tr>{['Community', 'City', 'Distance', 'IL Rate', 'AL Rate', 'MC Rate', 'Occupancy', 'Notes', ''].map((h, i) => <th key={i} className={TH}>{h}</th>)}</tr>
            </thead>
            <tbody>
              {competitors.map((c, i) => (
                <tr key={i} className="hover:bg-white/[0.02]">
                  <td className={`${TD} font-bold text-[#f4f8ff]`}>{c.name}</td>
                  <td className={TD}>{c.city}</td>
                  <td className={TD}>{c.dist} mi</td>
                  <td className={TD}>{c.il}</td>
                  <td className={TD}>{c.al}</td>
                  <td className={TD}>{c.mc}</td>
                  <td className={TD}><Badge tone={occTone(c.occ)}>{c.occ}</Badge></td>
                  <td className={`${TD} max-w-[140px] text-[11px] text-[#6b7fa3]`}>{c.notes}</td>
                  <td className={TD}><DemoButton variant="x" sm onClick={() => actions.toast('Competitor notes updated!')}>Edit</DemoButton></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <Card title="Rate Comparison (AL)">
          {RATE_COMPARE.map(([name, rate, color]) => (
            <div key={name} className="flex justify-between border-b border-white/[0.04] py-[7px]">
              <span className="text-[12px] text-[#c8d6e8]">{name}</span>
              <span className="text-[13px] font-bold" style={{ color }}>{rate}</span>
            </div>
          ))}
        </Card>
        <Card title="Market Summary">
          <div className="text-[12px] leading-[1.8] text-[#6b7fa3]">
            <div className="mb-2 font-bold text-[#f4f8ff]">February 2026</div>
            <div>• Your AL rate ($4,100) is <span className="text-[#4fc87a]">below market avg</span> ($4,375) — opportunity to increase</div>
            <div>• Cottonwood Creek offering 1st month free — counter with amenities</div>
            <div>• Heritage Pines on waitlist for 2BR — capture overflow demand</div>
            <div>• Meadowbrook renovation attracting premium move-ins</div>
          </div>
          <DemoButton sm className="mt-3" onClick={() => actions.toast('Rate review meeting scheduled for next Monday!')}>Schedule Rate Review</DemoButton>
        </Card>
      </div>
    </>
  );
}
