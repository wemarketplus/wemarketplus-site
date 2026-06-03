import { useRef, useState } from 'react';
import { Card, DemoButton, Field, FI, StatGrid, StatTile, TBL, TD, TH } from '@/shared/cl-demo';
import { MILEAGE_EXPENSE_TYPES } from '../constants/maxData';
import { useMaxDemo } from '../hooks/useMaxDemo';
import { todayIso } from '../utils/maxDate';

// Reproduces rMileage(): trip-log form (with receipt upload), trip history, and
// a monthly summary.
export function MileageTab() {
  const { mileageLogs, mileageRate, actions } = useMaxDemo();
  const fileRef = useRef<HTMLInputElement>(null);
  const [date, setDate] = useState(todayIso());
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [miles, setMiles] = useState('');
  const [estimated, setEstimated] = useState(false);
  const [purpose, setPurpose] = useState('');
  const [expType, setExpType] = useState('');
  const [expAmt, setExpAmt] = useState('');
  const [expNotes, setExpNotes] = useState('');
  const [fileName, setFileName] = useState('');

  const milesNum = parseFloat(miles) || 0;
  const onToBlurEstimate = (val: string) => {
    setTo(val);
    if (val.length > 5 && !miles) {
      setMiles((Math.random() * 20 + 5).toFixed(1));
      setEstimated(true);
    }
  };

  const submit = () => {
    if (!from.trim() || !to.trim()) { actions.toast('From and To addresses are required', true); return; }
    if (!milesNum) { actions.toast('Enter mileage', true); return; }
    const reimb = parseFloat((milesNum * mileageRate).toFixed(2));
    actions.addMileageLog({ date: date || todayIso(), from_addr: from.trim(), to_addr: to.trim(), miles: milesNum, purpose, reimbursement: reimb, receipt: fileName || null, expense_type: expType, expense_amt: parseFloat(expAmt) || 0 }, !!fileName);
    setFrom(''); setTo(''); setMiles(''); setPurpose(''); setExpAmt(''); setExpNotes(''); setFileName(''); setEstimated(false);
  };

  const now = new Date();
  const monthly = mileageLogs.filter((l) => { const d = new Date(l.date); return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear(); });
  const totalMiles = mileageLogs.reduce((s, l) => s + l.miles, 0);
  const totalReimb = mileageLogs.reduce((s, l) => s + l.reimbursement, 0);
  const pendingCount = mileageLogs.filter((l) => l.status === 'pending').length;

  return (
    <>
      <StatGrid>
        <StatTile label="Total Miles" value={totalMiles.toFixed(1)} sub="All logged trips" />
        <StatTile label="Reimbursement" value={`$${totalReimb.toFixed(2)}`} valueClassName="text-[#4fc87a]" sub={`@ $${mileageRate}/mile`} />
        <StatTile label="Pending Approval" value={pendingCount} valueClassName="text-[#f59e0b]" sub="Awaiting admin review" />
        <StatTile label="Mileage Rate" value={`$${mileageRate}`} sub="Per mile — Admin editable" />
      </StatGrid>

      <div className="grid grid-cols-1 gap-[14px] lg:grid-cols-2">
        <Card title="Log New Trip">
          <div className="flex flex-col gap-2.5">
            <Field label="Date"><input className={FI} type="date" value={date} onChange={(e) => setDate(e.target.value)} /></Field>
            <Field label="From Address *"><input className={FI} placeholder="Office, Dallas TX" value={from} onChange={(e) => setFrom(e.target.value)} /></Field>
            <Field label="To Address *"><input className={FI} placeholder="Baylor Medical, Dallas TX" value={to} onChange={(e) => onToBlurEstimate(e.target.value)} /></Field>
            <div className={FL_GAP}>
              <div className="text-[11px] font-bold text-[#4b6278]">Mileage {estimated && <span className="text-[10px] font-normal text-[#4fc87a]">(estimated — verify before submitting)</span>}</div>
              <input className={FI} type="number" step={0.1} placeholder="Auto-calculated or enter manually" value={miles} onChange={(e) => setMiles(e.target.value)} />
              <div className="mt-1 text-[11px] text-[#6b7fa3]">Reimbursement: <strong className="text-[#4fc87a]">${(milesNum * mileageRate).toFixed(2)}</strong></div>
            </div>
            <Field label="Purpose"><input className={FI} placeholder="Referral visit, in-service, tour coordination…" value={purpose} onChange={(e) => setPurpose(e.target.value)} /></Field>

            <div className="rounded-[8px] border border-[#f59e0b]/15 bg-[#f59e0b]/[0.06] p-3">
              <div className="mb-2 text-[11px] font-bold uppercase tracking-[0.04em] text-[#f59e0b]">Additional Expense (Optional)</div>
              <div className="flex flex-col gap-2">
                <Field label="Expense Category"><select className={FI} value={expType} onChange={(e) => setExpType(e.target.value)}><option value="">None</option>{MILEAGE_EXPENSE_TYPES.map((t) => <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>)}</select></Field>
                <Field label="Expense Amount ($)"><input className={FI} type="number" step={0.01} placeholder="0.00" value={expAmt} onChange={(e) => setExpAmt(e.target.value)} /></Field>
                <Field label="Notes"><input className={FI} placeholder="Parking at hospital, client lunch…" value={expNotes} onChange={(e) => setExpNotes(e.target.value)} /></Field>
                <div className={FL_GAP}>
                  <div className="text-[11px] font-bold text-[#4b6278]">Receipt Upload</div>
                  <div onClick={() => fileRef.current?.click()} className="cursor-pointer rounded-[8px] border-2 border-dashed border-[#f59e0b]/30 p-4 text-center transition-colors hover:border-[#f59e0b]/60">
                    <div className="mb-1.5 text-[20px]">📎</div>
                    <div className="text-[12px] font-bold text-[#f59e0b]">{fileName ? `✅ ${fileName}` : 'Click or drag to upload receipt'}</div>
                    <div className="mt-0.5 text-[10px] text-[#6b7fa3]">PDF, JPG, PNG, HEIC accepted</div>
                  </div>
                  <input ref={fileRef} type="file" accept=".pdf,.jpg,.jpeg,.png,.heic,.heif" className="hidden" onChange={(e) => setFileName(e.target.files?.[0]?.name || '')} />
                </div>
              </div>
            </div>
            <DemoButton className="mt-2" onClick={submit}>💾 Submit Mileage Log</DemoButton>
          </div>
        </Card>

        <div>
          <Card title="Trip History" action={<DemoButton variant="x" sm onClick={() => actions.toast('Refreshed')}>↻ Refresh</DemoButton>}>
            <div className="overflow-x-auto">
              <table className={TBL}>
                <thead>
                  <tr>{['Date', 'Route', 'Miles', 'Reimb.', 'Expense', 'Status', 'Receipt'].map((h) => <th key={h} className={TH}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {mileageLogs.map((l) => (
                    <tr key={l.id} className="hover:bg-white/[0.02]">
                      <td className={`${TD} whitespace-nowrap text-[11px]`}>{l.date}</td>
                      <td className={TD}><div className="text-[11px] text-[#c8d6e8]">{l.from_addr}</div><div className="text-[10px] text-[#6b7fa3]">→ {l.to_addr}</div><div className="mt-px text-[10px] text-[#4b6278]">{l.purpose}</div></td>
                      <td className={`${TD} font-bold text-[#f4f8ff]`}>{l.miles.toFixed(1)}</td>
                      <td className={`${TD} font-bold text-[#4fc87a]`}>${l.reimbursement.toFixed(2)}</td>
                      <td className={TD}>{l.expense_amt > 0 ? <><div className="text-[11px]">${l.expense_amt.toFixed(2)}</div><div className="text-[10px] text-[#6b7fa3]">{l.expense_type}</div></> : <span className="text-[#4b6278]">—</span>}</td>
                      <td className={TD}><span className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-bold ${l.status === 'approved' ? 'bg-[#4fc87a]/10 text-[#4fc87a]' : l.status === 'rejected' ? 'bg-[#f87171]/10 text-[#f87171]' : 'bg-[#f59e0b]/10 text-[#f59e0b]'}`}>{l.status}</span></td>
                      <td className={TD}>{l.receipt ? <span title="Receipt uploaded">📎</span> : <span className="text-[11px] text-[#4b6278]">None</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title="Monthly Summary">
            <div className="grid grid-cols-3 gap-2.5 text-[12px]">
              {[['Miles this month', monthly.reduce((s, l) => s + l.miles, 0).toFixed(1), 'mi'], ['Mileage reimb.', '$' + monthly.reduce((s, l) => s + l.reimbursement, 0).toFixed(2), ''], ['Extra expenses', '$' + monthly.reduce((s, l) => s + (l.expense_amt || 0), 0).toFixed(2), '']].map((row) => (
                <div key={row[0]} className="rounded-[8px] bg-[#060e1b] p-2.5 text-center">
                  <div className="text-[10px] text-[#6b7fa3]">{row[0]}</div>
                  <div className="mt-0.5 text-[18px] font-black text-[#f4f8ff]">{row[1]}</div>
                  <div className="text-[10px] text-[#4b6278]">{row[2]}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}

const FL_GAP = 'flex flex-col gap-1';
